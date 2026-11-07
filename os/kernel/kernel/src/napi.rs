//! P8 — adaptive NAPI data plane. Retires spin-poll-forever (ARCHITECTURE.md §5,
//! "right-size for edge"): each service call drains a bounded BUDGET of frames,
//! then adapts.
//!   * budget EXHAUSTED (processed == budget) ⇒ the RX ring is under load: stay
//!     in POLL mode and GROW the budget (×2, capped at `max`) — amortize the
//!     per-IRQ cost and bound tail latency under load.
//!   * processed < budget ⇒ the ring drained/went quiet: SHRINK the budget
//!     toward `min`, re-arm the RX IRQ, and go IDLE (the caller WFIs until the
//!     next RX interrupt) — so an idle box burns no CPU.
//! This bounds latency under load AND CPU under idle, adaptively — the
//! edge-appropriate 1–2.5 GbE data plane, not a 100 GbE spin loop.

/// What the caller should do after a NAPI service call.
#[derive(PartialEq, Clone, Copy)]
pub enum Outcome {
    /// Ring still busy — call `service` again immediately (stay in poll mode).
    Continue,
    /// Ring quiet — re-arm the RX IRQ and idle (WFI) until it fires.
    Idle,
}

/// An adaptive NAPI poll-budget state machine (one per RX queue).
pub struct Napi {
    budget: u32,
    min: u32,
    max: u32,
    idle: bool,
    rearms: u32,
    services: u32,
    max_budget_seen: u32,
    total_processed: u64,
}

impl Napi {
    pub const fn new(min: u32, max: u32) -> Self {
        Napi {
            budget: min,
            min,
            max,
            idle: true,
            rearms: 0,
            services: 0,
            max_budget_seen: min,
            total_processed: 0,
        }
    }

    /// One NAPI service: drain up to `budget` frames via `drain(budget) ->
    /// processed`, then adapt the budget and decide poll-vs-idle.
    pub fn service<F: FnMut(u32) -> u32>(&mut self, mut drain: F) -> Outcome {
        self.idle = false;
        self.services += 1;
        let processed = drain(self.budget);
        self.total_processed += processed as u64;
        if processed >= self.budget {
            // Under load: grow the budget (×2, capped).
            self.budget = self.budget.saturating_mul(2).min(self.max);
            if self.budget > self.max_budget_seen {
                self.max_budget_seen = self.budget;
            }
            Outcome::Continue
        } else {
            // Quiet: shrink toward min, re-arm the IRQ, idle.
            self.budget = (self.budget / 2).max(self.min);
            self.idle = true;
            self.rearms += 1;
            Outcome::Idle
        }
    }

    pub fn budget(&self) -> u32 {
        self.budget
    }
    pub fn rearms(&self) -> u32 {
        self.rearms
    }
    pub fn max_budget(&self) -> u32 {
        self.max_budget_seen
    }
    pub fn services(&self) -> u32 {
        self.services
    }
    pub fn total_processed(&self) -> u64 {
        self.total_processed
    }
    pub fn is_idle(&self) -> bool {
        self.idle
    }
}
