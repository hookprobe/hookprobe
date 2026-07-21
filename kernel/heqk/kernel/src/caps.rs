//! P2 — the object-capability system (arch-neutral; needs no HAL).
//!
//! Models seL4's design (see `CAPABILITY_MODEL.md`): memory begins as **Untyped**
//! and is carved into typed objects by **retype**; capabilities live in **CNode**
//! slots (a thread's CSpace) and are named by slot index (CPtr); a **capability
//! derivation tree** (parent links) lets **revoke** delete a whole subtree
//! synchronously — no GC pause — and reclaim the untyped memory.
//!
//! P2 models the derivation + revocation + memory accounting. Untyped is backed
//! by nominal physical ranges here; wiring it to the real frame allocator is a
//! P1b/P2-real follow-up. Type safety is enforced by the `ObjType` tag: a cap of
//! one type can never be used as another.

/// Object kinds an Untyped can be retyped into. Stable codes so a capability's
/// type can be returned to userspace across the syscall boundary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum ObjType {
    Untyped = 0,
    CNode = 1,
    Endpoint = 2,
    Frame = 3,
    Tcb = 4,
}

impl ObjType {
    pub fn code(self) -> u64 {
        self as u64
    }
    pub fn name(self) -> &'static str {
        match self {
            ObjType::Untyped => "Untyped",
            ObjType::CNode => "CNode",
            ObjType::Endpoint => "Endpoint",
            ObjType::Frame => "Frame",
            ObjType::Tcb => "Tcb",
        }
    }
}

// Access rights (bitmask). Presence of the cap is authorization; rights refine it.
pub const R: u8 = 1 << 0; // read
pub const W: u8 = 1 << 1; // write
pub const G: u8 = 1 << 2; // grant (may delegate copies)

/// A capability held in a CNode slot: an unforgeable reference to a kernel
/// object + rights + its place in the derivation tree.
#[derive(Clone)]
pub struct Cap {
    pub otype: ObjType,
    pub rights: u8,
    pub base: usize,          // object's physical base (nominal in P2)
    pub size: usize,          // object's size in bytes
    pub watermark: usize,     // Untyped only: bytes already retyped
    pub parent: Option<usize>, // derivation parent slot (None = root)
}

const SLOTS: usize = 64;

/// A capability space: one root CNode of `SLOTS` slots (nested CSpaces later).
pub struct CapSpace {
    slots: [Option<Cap>; SLOTS],
}

fn align16(n: usize) -> usize {
    (n + 15) & !15
}

impl CapSpace {
    /// Create a CSpace whose slot 0 holds a root Untyped over [base, base+size).
    pub fn with_root_untyped(base: usize, size: usize) -> Self {
        let mut s = CapSpace {
            slots: [const { None }; SLOTS],
        };
        s.slots[0] = Some(Cap {
            otype: ObjType::Untyped,
            rights: R | W | G,
            base,
            size,
            watermark: 0,
            parent: None,
        });
        s
    }

    fn free_slot(&self) -> Option<usize> {
        (0..SLOTS).find(|&i| self.slots[i].is_none())
    }

    /// Number of live capabilities.
    pub fn count(&self) -> usize {
        self.slots.iter().filter(|c| c.is_some()).count()
    }

    pub fn get(&self, slot: usize) -> Option<&Cap> {
        self.slots.get(slot).and_then(|c| c.as_ref())
    }

    /// Retype: carve one object of `otype`/`size` out of the Untyped at `ut_slot`.
    /// Returns the new slot, or an error string (kept as the sole allocation path
    /// — the kernel never mallocs; policy is here, in the caller's CSpace).
    pub fn retype(&mut self, ut_slot: usize, otype: ObjType, size: usize) -> Result<usize, &'static str> {
        let (base, need) = {
            let ut = self.slots.get(ut_slot).and_then(|c| c.as_ref()).ok_or("empty slot")?;
            if ut.otype != ObjType::Untyped {
                return Err("not an Untyped cap"); // type safety: can't retype a non-untyped
            }
            let need = align16(size.max(16));
            if ut.watermark + need > ut.size {
                return Err("out of untyped memory");
            }
            (ut.base + ut.watermark, need)
        };
        let dst = self.free_slot().ok_or("no free slot")?;
        // Bump the untyped watermark (this memory is now spoken for).
        self.slots[ut_slot].as_mut().unwrap().watermark += need;
        self.slots[dst] = Some(Cap {
            otype,
            rights: R | W | G,
            base,
            size: need,
            watermark: 0,
            parent: Some(ut_slot),
        });
        Ok(dst)
    }

    /// Depth in the derivation tree (root = 0), for pretty-printing.
    pub fn depth(&self, mut slot: usize) -> usize {
        let mut d = 0;
        while let Some(Some(c)) = self.slots.get(slot) {
            match c.parent {
                Some(p) => {
                    d += 1;
                    slot = p;
                }
                None => break,
            }
        }
        d
    }

    /// Recursively delete every capability derived from `slot` (its whole
    /// subtree), keep `slot` itself, and reclaim its Untyped memory. Synchronous,
    /// bounded, no garbage collector.
    pub fn revoke(&mut self, slot: usize) {
        let children: [usize; SLOTS] = core::array::from_fn(|i| i);
        for &ch in children.iter() {
            let is_child = self
                .slots
                .get(ch)
                .and_then(|c| c.as_ref())
                .map_or(false, |c| c.parent == Some(slot));
            if is_child {
                self.revoke(ch); // delete ch's descendants first
                self.slots[ch] = None; // then ch itself
            }
        }
        // Reclaim untyped memory now that nothing is derived from it.
        if let Some(c) = self.slots[slot].as_mut() {
            if c.otype == ObjType::Untyped {
                c.watermark = 0;
            }
        }
    }

    /// Type-safe view: succeeds only if the cap really is a Frame.
    pub fn as_frame(&self, slot: usize) -> Result<&Cap, &'static str> {
        match self.get(slot) {
            Some(c) if c.otype == ObjType::Frame => Ok(c),
            Some(_) => Err("type mismatch: not a Frame"),
            None => Err("empty slot"),
        }
    }

    /// Print the derivation tree (creation order == ascending slot == parents first).
    pub fn print_tree(&self) {
        for i in 0..SLOTS {
            if let Some(c) = &self.slots[i] {
                for _ in 0..self.depth(i) {
                    arch_aarch64::_print(format_args!("    "));
                }
                arch_aarch64::_print(format_args!(
                    "[{}] {:?}  {} B\n",
                    i, c.otype, c.size
                ));
            }
        }
    }
}
