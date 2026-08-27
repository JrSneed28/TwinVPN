//! Two-tier deficit round robin (ADR-0005 §11.5).
//!
//! > **Scheduling is two-tier deficit round robin**: outer DRR across
//! > `relay_sub`, inner DRR across that subject's half-flows, so one device
//! > holding 64 flows cannot starve a device holding one (I7).
//!
//! The two tiers are the whole point. A single-tier DRR over half-flows gives a
//! device with 64 flows 64× the service of a device with one, which is exactly the
//! starvation I7 forbids. The outer tier makes service fair *per subject*; the
//! inner tier makes it fair *within* a subject.
//!
//! The scheduler is a pure state machine over registered `(subject, flow)` pairs.
//! It moves no bytes and holds no payload — it answers "whose turn, and for how
//! many bytes", which keeps it testable and keeps the payload out of it.

use std::collections::VecDeque;

use crate::flow::FlowId;
use crate::subject::RelaySub;

/// The bytes of credit a queue earns per round. One MTU-ish quantum, so a single
/// large frame is never permanently starved by a stream of small ones.
pub const DEFAULT_QUANTUM: u32 = 1_500;

#[derive(Debug)]
struct FlowQueueState {
    flow: FlowId,
    deficit: u32,
    backlog: VecDeque<usize>,
}

#[derive(Debug)]
struct SubjectQueueState {
    subject: RelaySub,
    deficit: u32,
    flows: VecDeque<FlowQueueState>,
}

/// A two-tier deficit round-robin scheduler.
#[derive(Debug)]
pub struct TwoTierDrr {
    quantum: u32,
    subjects: VecDeque<SubjectQueueState>,
}

impl TwoTierDrr {
    /// A scheduler with `quantum` bytes of credit per round.
    #[must_use]
    pub fn new(quantum: u32) -> Self {
        Self {
            quantum: quantum.max(1),
            subjects: VecDeque::new(),
        }
    }

    /// The default 1 500-byte quantum.
    #[must_use]
    pub fn with_default_quantum() -> Self {
        Self::new(DEFAULT_QUANTUM)
    }

    /// Enqueues a frame of `bytes` for `(subject, flow)`.
    pub fn enqueue(&mut self, subject: RelaySub, flow: FlowId, bytes: usize) {
        if let Some(s) = self.subjects.iter_mut().find(|s| s.subject == subject) {
            if let Some(f) = s.flows.iter_mut().find(|f| f.flow == flow) {
                f.backlog.push_back(bytes);
            } else {
                s.flows.push_back(FlowQueueState {
                    flow,
                    deficit: 0,
                    backlog: VecDeque::from([bytes]),
                });
            }
            return;
        }
        self.subjects.push_back(SubjectQueueState {
            subject,
            deficit: 0,
            flows: VecDeque::from([FlowQueueState {
                flow,
                deficit: 0,
                backlog: VecDeque::from([bytes]),
            }]),
        });
    }

    /// Whether anything is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subjects
            .iter()
            .all(|s| s.flows.iter().all(|f| f.backlog.is_empty()))
    }

    /// Dequeues the next frame, or `None` when nothing is ready.
    ///
    /// Returns `(subject, flow, bytes)`. The payload is not here: the caller
    /// keeps it, so the scheduler never touches ciphertext.
    pub fn dequeue(&mut self) -> Option<(RelaySub, FlowId, usize)> {
        let rounds = self.subjects.len().max(1) * 4;
        for _ in 0..rounds {
            let mut subject = self.subjects.pop_front()?;
            subject.deficit = subject.deficit.saturating_add(self.quantum);

            let inner_rounds = subject.flows.len().max(1) * 4;
            let mut taken = None;
            for _ in 0..inner_rounds {
                let Some(mut flow) = subject.flows.pop_front() else {
                    break;
                };
                if flow.backlog.is_empty() {
                    // Drop an empty flow queue rather than cycling it forever.
                    continue;
                }
                flow.deficit = flow.deficit.saturating_add(self.quantum);
                let head = *flow.backlog.front().expect("non-empty");
                let cost = u32::try_from(head).unwrap_or(u32::MAX);
                if flow.deficit >= cost && subject.deficit >= cost {
                    flow.deficit -= cost;
                    subject.deficit -= cost;
                    flow.backlog.pop_front();
                    taken = Some((subject.subject, flow.flow, head));
                    subject.flows.push_back(flow);
                    break;
                }
                subject.flows.push_back(flow);
            }

            let empty = subject.flows.iter().all(|f| f.backlog.is_empty());
            if !empty || taken.is_some() {
                self.subjects.push_back(subject);
            }
            if taken.is_some() {
                return taken;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(n: u8) -> RelaySub {
        RelaySub::from_verified_claim([n; 16])
    }

    #[test]
    fn a_device_holding_sixty_four_flows_cannot_starve_a_device_holding_one() {
        // The I7 property, as an arithmetic assertion rather than a claim.
        let mut d = TwoTierDrr::with_default_quantum();
        let greedy = sub(1);
        let modest = sub(2);
        for f in 0..64_u32 {
            for _ in 0..8 {
                d.enqueue(greedy, flow(f), 1_000);
            }
        }
        for _ in 0..8 {
            d.enqueue(modest, flow(1_000), 1_000);
        }

        let mut greedy_served = 0_usize;
        let mut modest_served = 0_usize;
        for _ in 0..16 {
            let Some((s, _, _)) = d.dequeue() else { break };
            if s == greedy {
                greedy_served += 1;
            } else {
                modest_served += 1;
            }
        }
        // Single-tier DRR would give the modest subject 1 in 65. Two-tier gives
        // it roughly half, which is what "cannot starve" means.
        assert!(
            modest_served * 3 >= greedy_served,
            "modest={modest_served} greedy={greedy_served}: the outer tier is not \
             protecting the one-flow subject"
        );
    }

    #[test]
    fn within_one_subject_the_flows_take_turns() {
        let mut d = TwoTierDrr::with_default_quantum();
        let s = sub(1);
        for _ in 0..4 {
            d.enqueue(s, flow(1), 100);
            d.enqueue(s, flow(2), 100);
        }
        let mut seen = Vec::new();
        while let Some((_, f, _)) = d.dequeue() {
            seen.push(f.get());
        }
        assert_eq!(seen.len(), 8);
        let ones = seen.iter().filter(|f| **f == 1).count();
        assert_eq!(ones, 4, "one flow did not monopolise the subject's share");
    }

    #[test]
    fn an_empty_scheduler_yields_nothing_and_does_not_spin() {
        let mut d = TwoTierDrr::with_default_quantum();
        assert!(d.is_empty());
        assert!(d.dequeue().is_none());
    }

    #[test]
    fn a_frame_larger_than_the_quantum_is_eventually_served() {
        let mut d = TwoTierDrr::new(100);
        d.enqueue(sub(1), flow(1), 250);
        // It cannot go on the first round, but it must not starve.
        let mut served = None;
        for _ in 0..8 {
            if let Some(x) = d.dequeue() {
                served = Some(x);
                break;
            }
        }
        assert_eq!(served.map(|(_, _, b)| b), Some(250));
    }

    fn flow(n: u32) -> FlowId {
        FlowId::new(n)
    }
}
