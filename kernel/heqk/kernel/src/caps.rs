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
/// Number of cap slots per CSpace (public, for callers that iterate a CSpace).
pub const SLOTS_PER_CSPACE: usize = SLOTS;

/// A capability space: one root CNode of `SLOTS` slots (nested CSpaces later).
pub struct CapSpace {
    slots: [Option<Cap>; SLOTS],
}

fn align16(n: usize) -> usize {
    (n + 15) & !15
}

impl CapSpace {
    /// Create a CSpace whose slot 0 holds a root Untyped over [base, base+size).
    /// An EMPTY CSpace (no caps). A child TCB starts here and is handed exactly the
    /// authority its spawner delegates via `mint_into` (CORE-2).
    pub fn empty() -> Self {
        CapSpace {
            slots: [const { None }; SLOTS],
        }
    }

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
            // Reject an out-of-range size BEFORE rounding, so align16() can't
            // overflow (wrap to a tiny `need` that passes the watermark check).
            if size > ut.size {
                return Err("request exceeds untyped");
            }
            let need = align16(size.max(16));
            if ut.watermark + need > ut.size {
                return Err("out of untyped memory");
            }
            (ut.base + ut.watermark, need)
        };
        let dst = self.free_slot().ok_or("no free slot")?;
        // Bump the untyped watermark (this memory is now spoken for). Graceful,
        // not `unwrap` — `ut_slot` was validated above, but never panic in a
        // runtime cap operation (fail-closed by returning an error instead).
        match self.slots.get_mut(ut_slot).and_then(|c| c.as_mut()) {
            Some(ut) => ut.watermark += need,
            None => return Err("untyped vanished mid-retype"),
        }
        // CORE-3/XC-7: ZERO the reclaimed Untyped memory before it backs the new
        // object. After a `revoke` resets the watermark, this same range may have
        // previously backed another tenant's object (e.g. a Frame holding secrets);
        // without scrubbing, retype would leak those stale bytes into the new cap.
        // seL4's reset-on-reuse. `base` is a kernel-accessible identity-mapped address
        // (Untyped is backed by real reserved physical memory).
        unsafe { core::ptr::write_bytes(base as *mut u8, 0, need) };
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

    /// Delete every capability derived from `slot` (its whole subtree), keep
    /// `slot` itself, and reclaim its Untyped memory. **Iterative** (no recursion
    /// — B-9): mark the transitive descendants by a fixpoint over the flat
    /// parent-linked array (bounded by SLOTS passes, no unbounded kernel stack),
    /// then delete them. Synchronous, no garbage collector.
    pub fn revoke(&mut self, slot: usize) {
        let mut doomed = [false; SLOTS];
        let mut changed = true;
        while changed {
            changed = false;
            for i in 0..SLOTS {
                if doomed[i] || i == slot {
                    continue;
                }
                if let Some(Some(c)) = self.slots.get(i) {
                    // Doomed iff its parent is `slot` or already-doomed (transitive).
                    if let Some(p) = c.parent {
                        if p == slot || (p < SLOTS && doomed[p]) {
                            doomed[i] = true;
                            changed = true;
                        }
                    }
                }
            }
        }
        for i in 0..SLOTS {
            if doomed[i] {
                self.slots[i] = None;
            }
        }
        // Reclaim untyped memory now that nothing is derived from it.
        if let Some(c) = self.slots[slot].as_mut() {
            if c.otype == ObjType::Untyped {
                c.watermark = 0;
            }
        }
    }

    /// Rights enforcement (B-9). Delegate a rights-DIMINISHED copy of the cap at
    /// `slot` into a fresh slot: the new cap references the SAME object but with
    /// rights `requested & source.rights` — rights can only be NARROWED, never
    /// amplified (the core capability property) — and only if the source holds the
    /// **Grant** right. Returns the new slot.
    pub fn mint(&mut self, slot: usize, requested: u8) -> Result<usize, &'static str> {
        let (otype, rights, base, size) = {
            let src = self.get(slot).ok_or("empty slot")?;
            if src.rights & G == 0 {
                return Err("mint requires the Grant right");
            }
            (src.otype, requested & src.rights, src.base, src.size)
        };
        let dst = self.free_slot().ok_or("no free slot")?;
        self.slots[dst] = Some(Cap { otype, rights, base, size, watermark: 0, parent: Some(slot) });
        Ok(dst)
    }

    /// CORE-2 — cross-CSpace DELEGATION: grant a rights-narrowed copy of `src_slot`
    /// FROM this CSpace INTO another TCB's CSpace `dst`. This is how an EL0 driver /
    /// P12 subscriber is handed EXACTLY the authority it should hold, and no more —
    /// requires the Grant right, and rights can only NARROW (`requested & src.rights`),
    /// never amplify. Returns the slot assigned in `dst`. (The delegated cap carries no
    /// `parent` link because the parent lives in a DIFFERENT CSpace; a cross-CSpace CDT
    /// for single-cap revoke needs the generation/CSpace-tagged MDB of CORE-9 — until
    /// then, teardown is whole-CSpace drop on TCB kill.)
    pub fn mint_into(
        &self,
        src_slot: usize,
        requested: u8,
        dst: &mut CapSpace,
    ) -> Result<usize, &'static str> {
        let src = self.get(src_slot).ok_or("empty slot")?;
        if src.rights & G == 0 {
            return Err("mint requires the Grant right");
        }
        let cap = Cap {
            otype: src.otype,
            rights: requested & src.rights,
            base: src.base,
            size: src.size,
            watermark: 0,
            parent: None,
        };
        let d = dst.free_slot().ok_or("no free slot in dst")?;
        dst.slots[d] = Some(cap);
        Ok(d)
    }

    /// The enforcement point on capability invocation: true only if the cap at
    /// `slot` holds ALL of the `need` rights.
    pub fn has_rights(&self, slot: usize, need: u8) -> bool {
        self.get(slot).map_or(false, |c| c.rights & need == need)
    }

    /// Type-safe **and** rights-checked Frame view: the cap must be a Frame AND
    /// hold every right in `need` (e.g. `W` before a write is granted).
    pub fn as_frame_rights(&self, slot: usize, need: u8) -> Result<&Cap, &'static str> {
        let c = self.as_frame(slot)?;
        if c.rights & need != need {
            return Err("insufficient rights");
        }
        Ok(c)
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
