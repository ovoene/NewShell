use std::sync::Condvar;

use super::terminal_struct::{RenderGatePhase, RenderGateState, RenderWaitResult, TabRenderGate};

impl TabRenderGate {
    pub(crate) fn new(min_interval: std::time::Duration) -> Self {
        Self {
            state: std::sync::Mutex::new(RenderGateState {
                requested: 0,
                settled: 0,
                phase: RenderGatePhase::Idle,
                closed: false,
                last_visible_flush: std::time::Instant::now() - min_interval,
            }),
            settled_cv: Condvar::new(),
        }
    }

    /// Register a snapshot request and return `(ticket, should_schedule)`.
    pub(crate) fn request(&self) -> Option<(u64, bool)> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return None;
        }
        state.requested = state.requested.saturating_add(1);
        let ticket = state.requested;
        let should_schedule = state.phase == RenderGatePhase::Idle;
        if should_schedule {
            state.phase = RenderGatePhase::Scheduled;
        }
        Some((ticket, should_schedule))
    }

    pub(crate) fn flush_delay(&self, min_interval: std::time::Duration) -> std::time::Duration {
        let state = self.state.lock().unwrap();
        if state.closed {
            return std::time::Duration::ZERO;
        }
        min_interval.saturating_sub(state.last_visible_flush.elapsed())
    }

    /// Capture the newest request covered by the snapshot about to be built.
    pub(crate) fn begin_flush(&self) -> Option<u64> {
        let mut state = self.state.lock().unwrap();
        if state.closed || state.phase != RenderGatePhase::Scheduled {
            return None;
        }
        state.phase = RenderGatePhase::Flushing;
        Some(state.requested)
    }

    /// Settle all requests covered by a UI flush and report whether another
    /// request arrived after `begin_flush` captured its generation.
    pub(crate) fn finish_flush(&self, through: u64, visible: bool) -> bool {
        let mut state = self.state.lock().unwrap();
        state.settled = state.settled.max(through);
        if visible {
            state.last_visible_flush = std::time::Instant::now();
        }

        let reschedule = !state.closed && state.requested > through;
        state.phase = if reschedule {
            RenderGatePhase::Scheduled
        } else {
            RenderGatePhase::Idle
        };
        self.settled_cv.notify_all();
        reschedule
    }

    pub(crate) fn wait_for(&self, ticket: u64, timeout: std::time::Duration) -> RenderWaitResult {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .settled_cv
            .wait_timeout_while(state, timeout, |state| {
                state.settled < ticket && !state.closed
            })
            .unwrap();
        if state.settled >= ticket {
            RenderWaitResult::Settled
        } else if state.closed {
            RenderWaitResult::Closed
        } else {
            RenderWaitResult::TimedOut
        }
    }

    pub(crate) fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.phase = RenderGatePhase::Idle;
        self.settled_cv.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    const MIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(33);

    #[test]
    fn completion_before_wait_is_observed_without_a_lost_wakeup() {
        let gate = TabRenderGate::new(MIN_INTERVAL);
        let (ticket, should_schedule) = gate.request().unwrap();
        assert!(should_schedule);
        let through = gate.begin_flush().unwrap();
        assert!(!gate.finish_flush(through, true));
        assert_eq!(
            gate.wait_for(ticket, std::time::Duration::from_secs(1)),
            RenderWaitResult::Settled
        );
    }

    #[test]
    fn an_old_snapshot_does_not_settle_a_new_request() {
        let gate = TabRenderGate::new(MIN_INTERVAL);
        let (_, should_schedule) = gate.request().unwrap();
        assert!(should_schedule);
        let first = gate.begin_flush().unwrap();

        let (second_ticket, should_schedule) = gate.request().unwrap();
        assert!(!should_schedule);
        assert!(gate.finish_flush(first, true));
        assert_eq!(
            gate.wait_for(second_ticket, std::time::Duration::ZERO),
            RenderWaitResult::TimedOut
        );

        let second = gate.begin_flush().unwrap();
        assert!(!gate.finish_flush(second, true));
        assert_eq!(
            gate.wait_for(second_ticket, std::time::Duration::ZERO),
            RenderWaitResult::Settled
        );
    }

    #[test]
    fn requests_coalesce_without_an_unconditional_trailing_flush() {
        let gate = TabRenderGate::new(MIN_INTERVAL);
        let (_, first_schedules) = gate.request().unwrap();
        let (second_ticket, second_schedules) = gate.request().unwrap();
        assert!(first_schedules);
        assert!(!second_schedules);

        let through = gate.begin_flush().unwrap();
        assert!(!gate.finish_flush(through, true));
        assert!(gate.begin_flush().is_none());
        assert_eq!(
            gate.wait_for(second_ticket, std::time::Duration::ZERO),
            RenderWaitResult::Settled
        );
    }

    #[test]
    fn closing_a_gate_wakes_waiters() {
        let gate = Arc::new(TabRenderGate::new(MIN_INTERVAL));
        let (ticket, _) = gate.request().unwrap();
        let waiter_gate = gate.clone();
        let waiter = std::thread::spawn(move || {
            waiter_gate.wait_for(ticket, std::time::Duration::from_secs(5))
        });

        gate.close();
        assert_eq!(waiter.join().unwrap(), RenderWaitResult::Closed);
        assert!(gate.request().is_none());
        assert!(gate.begin_flush().is_none());
    }

    #[test]
    fn hidden_flushes_settle_without_throttling_the_next_request() {
        let gate = TabRenderGate::new(MIN_INTERVAL);
        gate.request().unwrap();
        let through = gate.begin_flush().unwrap();
        assert!(!gate.finish_flush(through, false));

        let (_, should_schedule) = gate.request().unwrap();
        assert!(should_schedule);
        assert_eq!(gate.flush_delay(MIN_INTERVAL), std::time::Duration::ZERO);
    }
}
