//! The AP's parked-station-frame ring (COR-M4 + P5): station frames read by a control request or
//! by the WPA2 authenticator while the AP serves are parked here instead of discarded, and the
//! serve loop delivers them first, in order. Pure + generic so QEMU proves the same code the CM5
//! runs (`[P11-defer]`).

/// FIFO of up to `N` frames of up to `SZ` bytes, each with (channel, length, data offset).
pub struct DeferRing<const N: usize, const SZ: usize> {
    buf: [[u8; SZ]; N],
    meta: [(u8, u16, usize); N],
    head: usize,
    len: usize,
    pub on: bool,
    /// [parked, delivered, dropped because the ring was full]
    pub diag: [u32; 3],
}

impl<const N: usize, const SZ: usize> DeferRing<N, SZ> {
    pub const fn new() -> Self {
        DeferRing { buf: [[0; SZ]; N], meta: [(0, 0, 0); N], head: 0, len: 0, on: false, diag: [0; 3] }
    }

    /// Enable/disable parking; either way the ring is emptied.
    pub fn set(&mut self, on: bool) {
        self.on = on;
        self.head = 0;
        self.len = 0;
    }

    /// Park a station frame (channel 1 = event, 2 = data). Inert when off; full = counted drop.
    pub fn push(&mut self, rx: &[u8], ch: u8, len: u16, doff: usize) {
        if !self.on || !(ch == 1 || ch == 2) {
            return;
        }
        if self.len == N {
            self.diag[2] += 1;
            return;
        }
        let i = (self.head + self.len) % N;
        let n = (len as usize).min(rx.len()).min(SZ);
        self.buf[i][..n].copy_from_slice(&rx[..n]);
        self.meta[i] = (ch, n as u16, doff);
        self.len += 1;
        self.diag[0] += 1;
    }

    /// The oldest parked frame, copied into `rx`.
    pub fn pop(&mut self, rx: &mut [u8]) -> Option<(u8, u16, usize)> {
        if self.len == 0 {
            return None;
        }
        let i = self.head;
        let (ch, n, doff) = self.meta[i];
        let n = (n as usize).min(rx.len());
        rx[..n].copy_from_slice(&self.buf[i][..n]);
        self.head = (self.head + 1) % N;
        self.len -= 1;
        self.diag[1] += 1;
        Some((ch, n as u16, doff))
    }

    /// Remove the FIRST parked frame `pick(frame, channel, data_offset)` accepts (copied into `rx`)
    /// and return (its result, its data offset); every other parked frame keeps its order.
    pub fn take<R>(&mut self, rx: &mut [u8], mut pick: impl FnMut(&[u8], u8, usize) -> Option<R>) -> Option<(R, usize)> {
        for k in 0..self.len {
            let i = (self.head + k) % N;
            let (ch, n, doff) = self.meta[i];
            let n = (n as usize).min(rx.len());
            let Some(r) = pick(&self.buf[i][..n], ch, doff) else { continue };
            rx[..n].copy_from_slice(&self.buf[i][..n]);
            for j in k..self.len - 1 {
                let dst = (self.head + j) % N;
                let src = (self.head + j + 1) % N;
                self.buf[dst] = self.buf[src];
                self.meta[dst] = self.meta[src];
            }
            self.len -= 1;
            self.diag[1] += 1;
            return Some((r, doff));
        }
        None
    }
}

/// `[P11-defer]` — inert when off, FIFO across wrap-around, a full ring counts the drop, and
/// `take` removes ONLY the matching entry while the rest keep their order.
pub fn defer_selftest() -> bool {
    const N: usize = 8;
    let mut r: DeferRing<N, 64> = DeferRing::new();
    let mut rx = [0u8; 64];
    let mark = |k: u8| {
        let mut f = [0u8; 32];
        f[20] = k;
        f
    };
    r.push(&mark(9), 2, 32, 0);
    let inert = r.pop(&mut rx).is_none();
    r.set(true);
    for k in 0..N as u8 {
        r.push(&mark(k), 2, 32, 4);
    }
    r.push(&mark(200), 2, 32, 4);
    let full_counted = r.diag[2] == 1;
    for _ in 0..N / 2 {
        let _ = r.pop(&mut rx);
    }
    for k in 0..(N / 2) as u8 {
        r.push(&mark(100 + k), 1, 32, 4); // the live window now straddles the end
    }
    let took = r.take(&mut rx, |f, ch, _| (ch == 1 && f[20] == 102).then_some(())).is_some() && rx[20] == 102;
    let mut expect = [0u8; N];
    let mut ne = 0;
    for k in (N / 2) as u8..N as u8 {
        expect[ne] = k;
        ne += 1;
    }
    for k in 0..(N / 2) as u8 {
        if k != 2 {
            expect[ne] = 100 + k;
            ne += 1;
        }
    }
    let mut order = true;
    for e in expect[..ne].iter() {
        match r.pop(&mut rx) {
            Some(_) if rx[20] == *e => {}
            _ => order = false,
        }
    }
    let empty = r.pop(&mut rx).is_none() && r.take(&mut rx, |_, _, _| Some(())).is_none();
    let ignored_ctrl = {
        r.push(&mark(1), 0, 32, 4); // control channel: never parked
        r.pop(&mut rx).is_none()
    };
    inert && full_counted && took && order && empty && ignored_ctrl
}
