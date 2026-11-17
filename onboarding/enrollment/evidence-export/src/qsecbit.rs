//! A sliding-window summary of the QSECBIT resilience score, carried in every HQX3 frame.
//!
//! The live v2 frame carries one score sample. The control plane needs the trend: the window
//! keeps the last `N` samples and summarises the ones inside `window_ms` of `now_ms` (count, min,
//! max, mean, last). The score is the device's own fixed-point `u32`, passed through unchanged.
//! Fixed capacity, no heap.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Samples inside the window (0 = no score yet: the other fields are 0).
    pub n: u16,
    /// Time from the oldest to the newest sample in the window.
    pub span_ms: u32,
    pub min: u32,
    pub max: u32,
    pub mean: u32,
    pub last: u32,
    pub last_ts_ms: u64,
}

pub struct Window<const N: usize> {
    ts: [u64; N],
    score: [u32; N],
    head: usize,
    len: usize,
}

impl<const N: usize> Default for Window<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Window<N> {
    pub const fn new() -> Self {
        Window { ts: [0; N], score: [0; N], head: 0, len: 0 }
    }

    /// Add a sample. A sample older than the newest one is ignored (clock steps never reorder
    /// the window); the oldest sample is dropped when the window is full.
    pub fn push(&mut self, ts_ms: u64, score: u32) {
        if N == 0 {
            return;
        }
        if self.len > 0 {
            let newest = self.ts[(self.head + N - 1) % N];
            if ts_ms < newest {
                return;
            }
        }
        self.ts[self.head] = ts_ms;
        self.score[self.head] = score;
        self.head = (self.head + 1) % N;
        if self.len < N {
            self.len += 1;
        }
    }

    /// Summarise the samples with `ts >= now_ms - window_ms`.
    pub fn summary(&self, now_ms: u64, window_ms: u64) -> Summary {
        let from = now_ms.saturating_sub(window_ms);
        let mut s = Summary { min: u32::MAX, ..Summary::default() };
        let mut sum: u64 = 0;
        let mut oldest = u64::MAX;
        for i in 0..self.len {
            let k = (self.head + N - self.len + i) % N; // oldest first
            if self.ts[k] < from || self.ts[k] > now_ms {
                continue;
            }
            let v = self.score[k];
            s.n += 1;
            sum += v as u64;
            s.min = s.min.min(v);
            s.max = s.max.max(v);
            s.last = v;
            s.last_ts_ms = self.ts[k];
            oldest = oldest.min(self.ts[k]);
        }
        if s.n == 0 {
            return Summary::default();
        }
        s.mean = (sum / s.n as u64) as u32;
        s.span_ms = (s.last_ts_ms - oldest).min(u32::MAX as u64) as u32;
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_slides() {
        let mut w: Window<4> = Window::new();
        assert_eq!(w.summary(100, 1000), Summary::default());
        for (t, v) in [(10, 50), (20, 70), (30, 60), (40, 90), (50, 30)] {
            w.push(t, v);
        }
        // capacity 4: (10,50) fell out
        let s = w.summary(50, 1000);
        assert_eq!((s.n, s.min, s.max, s.mean, s.last, s.span_ms), (4, 30, 90, 62, 30, 30));
        // time window: only ts >= 35
        let s = w.summary(50, 15);
        assert_eq!((s.n, s.min, s.max, s.last), (2, 30, 90, 30));
        // a sample from the past is ignored
        w.push(5, 1);
        assert_eq!(w.summary(50, 1000).min, 30);
    }
}
