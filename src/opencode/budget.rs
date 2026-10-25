//! Charge verification work without charging model repair time to its budget.
use std::time::{Duration, Instant};

pub struct VerificationBudget {
    overall_deadline: Instant,
    remaining: Duration,
}

impl VerificationBudget {
    pub fn new(overall_deadline: Instant) -> Self {
        Self {
            overall_deadline,
            remaining: super::verification::VERIFICATION_TIMEOUT,
        }
    }

    pub fn deadline_at(&self, now: Instant) -> Instant {
        self.overall_deadline.min(now + self.remaining)
    }

    pub fn charge(&mut self, elapsed: Duration) {
        self.remaining = self.remaining.saturating_sub(elapsed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_repair_does_not_consume_the_remaining_verification_budget() {
        let start = Instant::now();
        let mut budget = VerificationBudget::new(start + Duration::from_secs(1800));
        budget.charge(Duration::from_secs(5));
        let after_repair = start + Duration::from_secs(95);
        assert_eq!(
            budget.deadline_at(after_repair),
            after_repair + Duration::from_secs(115)
        );
    }

    #[test]
    fn retries_share_verification_work_and_never_extend_the_analysis_deadline() {
        let start = Instant::now();
        let overall_deadline = start + Duration::from_secs(100);
        let mut budget = VerificationBudget::new(overall_deadline);
        budget.charge(Duration::from_secs(10));
        assert_eq!(
            budget.deadline_at(start + Duration::from_secs(95)),
            overall_deadline
        );
        budget.charge(Duration::from_secs(110));
        assert_eq!(budget.deadline_at(start), start);
    }
}
