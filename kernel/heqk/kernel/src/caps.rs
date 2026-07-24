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
    // P12: async signalling objects. A cap of these types names a kernel object by
    // (index, generation) carried in `base`/`watermark`, plus a `badge` stamped at
    // mint time. `Notification` = a badge word + waiter (seL4-exact). `Topic` = a
    // pub-sub channel; `Topic{W}` may publish, `Topic{R}` may subscribe/receive.
    Notification = 5,
    Topic = 6,
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
            ObjType::Notification => "Notification",
            ObjType::Topic => "Topic",
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
    pub base: usize,          // object's physical base (nominal in P2) — P12: object INDEX
    pub size: usize,          // object's size in bytes
    pub watermark: usize,     // Untyped: bytes already retyped — P12: object GENERATION
    // CORE-9: derivation parent as (slot, generation-at-mint-time). None = root, or a
    // cross-CSpace delegation (parent lives in a different CSpace). The generation tag
    // makes a REUSED slot safe: once the parent slot is freed its CSpace generation is
    // bumped, so a stale child recording the OLD generation no longer matches the slot's
    // current occupant and is treated as an ORPHAN — never a descendant, never followed.
    pub parent: Option<(usize, u32)>,
    // P12: badge stamped at mint time on a Notification/Topic cap. `Signal`/`Publish`
    // use THIS, never a syscall argument — so a badge cannot be forged, only held.
    // Preserved (not amplifiable) across `mint`/`mint_into`. 0 for non-signal caps.
    pub badge: u64,
}

const SLOTS: usize = 64;
/// Number of cap slots per CSpace (public, for callers that iterate a CSpace).
pub const SLOTS_PER_CSPACE: usize = SLOTS;

/// A capability space: one root CNode of `SLOTS` slots (nested CSpaces later).
pub struct CapSpace {
    slots: [Option<Cap>; SLOTS],
    // CORE-9: per-slot GENERATION for the capability derivation tree. Bumped every
    // time a slot is freed (revoke), so a stale child's recorded (slot, gen) parent
    // link stops resolving the instant the slot is reused. Base 1 (0 is reserved to
    // mean "no cap / root"), monotonic per slot; wrap is astronomically distant.
    gen: [u32; SLOTS],
}

/// Generation a slot starts at. 0 is reserved (no-cap/root sentinel).
const GEN_BASE: u32 = 1;

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
            gen: [GEN_BASE; SLOTS],
        }
    }

    pub fn with_root_untyped(base: usize, size: usize) -> Self {
        let mut s = CapSpace {
            slots: [const { None }; SLOTS],
            gen: [GEN_BASE; SLOTS],
        };
        s.slots[0] = Some(Cap {
            otype: ObjType::Untyped,
            rights: R | W | G,
            base,
            size,
            watermark: 0,
            parent: None,
            badge: 0,
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

    /// CORE-9: current generation of a slot (the tag a child records at mint time).
    /// Out-of-range slots report 0 (the reserved sentinel — never a valid live tag).
    pub fn gen_of(&self, slot: usize) -> u32 {
        self.gen.get(slot).copied().unwrap_or(0)
    }

    /// CORE-9: is slot `i` a LIVE (non-stale) derivation child of slot `parent`?
    /// True iff `i`'s recorded parent link is `(parent, gen[parent])` — i.e. it was
    /// minted from the CURRENT occupant of `parent`, not a since-freed predecessor.
    fn is_live_child_of(&self, i: usize, parent: usize) -> bool {
        match self.slots.get(i).and_then(|c| c.as_ref()).and_then(|c| c.parent) {
            Some((p, g)) => p == parent && g == self.gen_of(parent),
            None => false,
        }
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
        // CORE-9: tag the parent link with the Untyped's CURRENT generation.
        let ut_gen = self.gen_of(ut_slot);
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
            parent: Some((ut_slot, ut_gen)),
            badge: 0,
        });
        Ok(dst)
    }

    /// Depth in the derivation tree (root = 0), for pretty-printing.
    pub fn depth(&self, mut slot: usize) -> usize {
        let mut d = 0;
        while let Some(Some(c)) = self.slots.get(slot) {
            match c.parent {
                // CORE-9: follow the link ONLY if its generation still matches the
                // parent slot's current occupant. A stale link (recorded gen != current
                // gen) is an ORPHAN: stop — do not follow it into an unrelated subtree.
                Some((p, g)) if g == self.gen_of(p) => {
                    d += 1;
                    slot = p;
                }
                _ => break,
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
                if let Some((p, g)) = self.slots[i].as_ref().and_then(|c| c.parent) {
                    // CORE-9: a link whose recorded generation no longer matches the
                    // parent slot's current occupant is STALE — the child was minted
                    // from a since-freed cap that merely shared this slot index. Treat
                    // it as an orphan: never a descendant, never followed.
                    if p >= SLOTS || g != self.gen_of(p) {
                        continue;
                    }
                    // Doomed iff its parent is `slot` or already-doomed (transitive).
                    if p == slot || doomed[p] {
                        doomed[i] = true;
                        changed = true;
                    }
                }
            }
        }
        for i in 0..SLOTS {
            if doomed[i] {
                self.slots[i] = None;
                // CORE-9: bump the freed slot's generation so any lingering stale
                // child pointing here (old gen) can never re-attach to a future reuse.
                self.gen[i] = self.gen[i].wrapping_add(1).max(GEN_BASE);
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
        let (otype, rights, base, size, watermark, badge) = {
            let src = self.get(slot).ok_or("empty slot")?;
            if src.rights & G == 0 {
                return Err("mint requires the Grant right");
            }
            // P12: carry the object identity (index=base, generation=watermark) and the
            // badge UNCHANGED — mint may only NARROW rights, never re-stamp a badge.
            (src.otype, requested & src.rights, src.base, src.size, src.watermark, src.badge)
        };
        let dst = self.free_slot().ok_or("no free slot")?;
        // CORE-9: tag the derivation link with the source slot's current generation.
        let parent = Some((slot, self.gen_of(slot)));
        self.slots[dst] = Some(Cap { otype, rights, base, size, watermark, parent, badge });
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
            // P12: preserve object identity (generation) + the badge across the CSpace
            // boundary; the delegated cap names the SAME object with (only) NARROWED rights.
            watermark: src.watermark,
            // CORE-9: parent stays None across a CSpace boundary. Generation tags are
            // per-CSpace (a `(slot, gen)` link only means anything WITHIN one CapSpace);
            // a cross-CSpace CDT would need the link to also carry a CSpace identity
            // (a full MDB). Out of scope here — cross-CSpace teardown remains whole-
            // CSpace drop on TCB kill, so a dangling delegated cap is never revoked
            // through a reused parent slot in the OTHER space.
            parent: None,
            badge: src.badge,
        };
        let d = dst.free_slot().ok_or("no free slot in dst")?;
        dst.slots[d] = Some(cap);
        Ok(d)
    }

    /// P12 — install a Notification/Topic object cap into a free slot: names the
    /// kernel object `(index, generation)` with `rights` and a `badge` stamped now.
    /// This is the STATIC, kernel-side object-cap creation (Microkit-style) — an EL0
    /// task can NEVER mint an object cap or a badge for itself; the kernel hands it
    /// exactly the authority it should hold (e.g. `Topic{W}` to a sensor driver, or
    /// `Topic{R}` to the rule engine). Returns the assigned slot.
    pub fn install_object(
        &mut self,
        otype: ObjType,
        rights: u8,
        index: usize,
        generation: u32,
        badge: u64,
    ) -> Result<usize, &'static str> {
        let dst = self.free_slot().ok_or("no free slot")?;
        self.slots[dst] = Some(Cap {
            otype,
            rights,
            base: index,
            size: 0,
            watermark: generation as usize,
            parent: None,
            badge,
        });
        Ok(dst)
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

/// CORE-9 `[P2-gen]` self-proof: a slot that is freed and then REUSED must not let a
/// stale child (one whose parent link records the slot's OLD generation) re-attach to
/// the new occupant. Runs kernel-side (needs private `slots`/`gen` access to implant a
/// stale child that OUTLIVED its parent — precisely the situation per-TCB CSpace churn
/// / cross-CSpace reuse creates, but which the public API alone cannot construct today).
/// `base` must be a real reserved region (retype zero-scrubs the backing memory).
pub fn core9_gen_selftest(base: usize) -> bool {
    let mut cs = CapSpace::with_root_untyped(base, 64 * 1024);

    // Normal derivation: root(0) -> parent P (a sub-Untyped) -> a real child of P.
    let p = match cs.retype(0, ObjType::Untyped, 8 * 1024) { Ok(s) => s, Err(_) => return false };
    let old_gen = cs.gen_of(p);
    let c = match cs.retype(p, ObjType::Frame, 1024) { Ok(s) => s, Err(_) => return false };
    // Capture the child's parent link = (P, old_gen). This is the value a *stale* child
    // keeps clutching after P is freed underneath it.
    let stale_link = match cs.slots.get(c).and_then(|x| x.as_ref()).and_then(|x| x.parent) {
        Some(l) => l, None => return false,
    };

    // Free slot P (reclaim the whole subtree, as a real teardown would): bumps gen[P].
    cs.revoke(0);
    let freed_and_bumped = stale_link == (p, old_gen) && cs.gen_of(p) != old_gen;

    // REUSE slot P with a brand-new object — retype lands in the lowest free slot (= P).
    let newcap = match cs.retype(0, ObjType::Frame, 1024) { Ok(s) => s, Err(_) => return false };
    let slot_reused = newcap == p && cs.gen_of(newcap) != old_gen;

    // Implant a cap that STILL records the old link (P, old_gen) in a fresh slot — a
    // stale child that survived its parent's death and now dangles at the reused slot.
    let stale_slot = match cs.free_slot() { Some(s) => s, None => return false };
    let mut stale = match cs.slots.get(newcap).and_then(|x| x.clone()) { Some(x) => x, None => return false };
    stale.parent = Some(stale_link); // (P, old_gen), pointing at the REUSED slot
    cs.slots[stale_slot] = Some(stale);

    // A genuine child of the NEW occupant (current generation) — the control. `mint`
    // derives a CDT child (parent = (newcap, current gen)) from the Frame's Grant right.
    let realchild = match cs.mint(newcap, R | W | G) { Ok(s) => s, Err(_) => return false };

    // PROOF: revoking the new cap deletes its real child but MUST spare the stale one,
    // and the stale link must not resolve as a live child of the reused slot.
    let not_descendant = !cs.is_live_child_of(stale_slot, newcap);
    cs.revoke(newcap);
    let stale_survived = cs.get(stale_slot).is_some();
    let real_deleted = cs.get(realchild).is_none();

    freed_and_bumped && slot_reused && not_descendant && stale_survived && real_deleted
}
