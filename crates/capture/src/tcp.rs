use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledChunk {
    pub bytes: Vec<u8>,
    pub fin: bool,
    pub rst: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblerResult {
    Pending,
    Advanced(AssembledChunk),
    GapDetected,
    ConflictDetected,
}

#[derive(Debug, Clone)]
struct PendingFragment {
    payload: Vec<u8>,
    fin: bool,
    rst: bool,
}

#[derive(Debug, Clone)]
struct DeliveredSegment {
    seq: u32,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TcpAssembler {
    next_seq: Option<u32>,
    pending: BTreeMap<u32, PendingFragment>,
    delivered: VecDeque<DeliveredSegment>,
    delivered_bytes: usize,
    history_limit: usize,
    max_gap: usize,
    degraded: bool,
}

impl Default for TcpAssembler {
    fn default() -> Self {
        Self {
            next_seq: None,
            pending: BTreeMap::new(),
            delivered: VecDeque::new(),
            delivered_bytes: 0,
            history_limit: 1024 * 1024,
            max_gap: 256 * 1024,
            degraded: false,
        }
    }
}

impl TcpAssembler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, seq: u32, payload: &[u8]) -> AssemblerResult {
        self.push_segment(seq, payload, false, false)
    }

    pub fn push_segment(
        &mut self,
        seq: u32,
        payload: &[u8],
        fin: bool,
        rst: bool,
    ) -> AssemblerResult {
        if self.degraded {
            return AssemblerResult::ConflictDetected;
        }
        if self.next_seq.is_none() {
            self.next_seq = Some(seq.wrapping_add(payload.len() as u32));
            self.record(seq, payload);
            return AssemblerResult::Advanced(AssembledChunk {
                bytes: payload.to_vec(),
                fin,
                rst,
            });
        }
        if payload.is_empty() {
            return if fin || rst {
                AssemblerResult::Advanced(AssembledChunk {
                    bytes: Vec::new(),
                    fin,
                    rst,
                })
            } else {
                AssemblerResult::Pending
            };
        }

        let next_seq = self.next_seq.expect("initialized");
        if seq > next_seq {
            let gap = seq.wrapping_sub(next_seq) as usize;
            if gap > self.max_gap {
                self.degraded = true;
                return AssemblerResult::GapDetected;
            }
            self.pending.entry(seq).or_insert_with(|| PendingFragment {
                payload: payload.to_vec(),
                fin,
                rst,
            });
            return AssemblerResult::Pending;
        }

        if self.is_exact_retransmit(seq, payload) && !fin && !rst {
            return AssemblerResult::Pending;
        }

        match self.accept_fragment(seq, payload, fin, rst) {
            AssemblerResult::Advanced(chunk) => self.flush_pending(chunk),
            other => other,
        }
    }

    pub fn finish(&mut self) -> AssemblerResult {
        if self.degraded || !self.pending.is_empty() {
            self.degraded = true;
            AssemblerResult::GapDetected
        } else {
            AssemblerResult::Pending
        }
    }

    fn accept_fragment(
        &mut self,
        seq: u32,
        payload: &[u8],
        fin: bool,
        rst: bool,
    ) -> AssemblerResult {
        let next_seq = self.next_seq.expect("initialized");
        if seq < next_seq {
            let overlap = next_seq.wrapping_sub(seq) as usize;
            if overlap >= payload.len() {
                return if self.match_overlap(seq, payload) {
                    AssemblerResult::Pending
                } else {
                    self.degraded = true;
                    AssemblerResult::ConflictDetected
                };
            }

            if !self.match_overlap(seq, &payload[..overlap]) {
                self.degraded = true;
                return AssemblerResult::ConflictDetected;
            }
            return self.accept_fragment(next_seq, &payload[overlap..], fin, rst);
        }

        self.next_seq = Some(seq.wrapping_add(payload.len() as u32));
        self.record(seq, payload);
        AssemblerResult::Advanced(AssembledChunk {
            bytes: payload.to_vec(),
            fin,
            rst,
        })
    }

    fn flush_pending(&mut self, mut current: AssembledChunk) -> AssemblerResult {
        while let Some(next_seq) = self.next_seq {
            let Some(fragment) = self.pending.remove(&next_seq) else {
                break;
            };
            match self.accept_fragment(next_seq, &fragment.payload, fragment.fin, fragment.rst) {
                AssemblerResult::Advanced(next) => {
                    current.bytes.extend_from_slice(&next.bytes);
                    current.fin |= next.fin;
                    current.rst |= next.rst;
                }
                other => return other,
            }
        }
        AssemblerResult::Advanced(current)
    }

    fn match_overlap(&self, seq: u32, payload: &[u8]) -> bool {
        let overlap_end = seq.wrapping_add(payload.len() as u32);
        let mut matched = 0usize;

        for segment in &self.delivered {
            let seg_end = segment.seq.wrapping_add(segment.bytes.len() as u32);
            if overlap_end <= segment.seq || seq >= seg_end {
                continue;
            }

            let start = seq.max(segment.seq);
            let end = overlap_end.min(seg_end);
            let seg_offset = start.wrapping_sub(segment.seq) as usize;
            let payload_offset = start.wrapping_sub(seq) as usize;
            let len = end.wrapping_sub(start) as usize;
            if segment.bytes[seg_offset..seg_offset + len]
                != payload[payload_offset..payload_offset + len]
            {
                return false;
            }
            matched += len;
        }

        matched == payload.len()
    }

    fn is_exact_retransmit(&self, seq: u32, payload: &[u8]) -> bool {
        self.delivered
            .iter()
            .any(|segment| segment.seq == seq && segment.bytes.as_slice() == payload)
    }

    fn record(&mut self, seq: u32, payload: &[u8]) {
        self.delivered.push_back(DeliveredSegment {
            seq,
            bytes: payload.to_vec(),
        });
        self.delivered_bytes += payload.len();
        while self.delivered_bytes > self.history_limit {
            let Some(segment) = self.delivered.pop_front() else {
                break;
            };
            self.delivered_bytes = self.delivered_bytes.saturating_sub(segment.bytes.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AssembledChunk, AssemblerResult, TcpAssembler};

    #[test]
    fn advances_first_segment_immediately() {
        let mut assembler = TcpAssembler::new();
        assert_eq!(
            assembler.push(100, b"hello"),
            AssemblerResult::Advanced(AssembledChunk {
                bytes: b"hello".to_vec(),
                fin: false,
                rst: false,
            })
        );
    }

    #[test]
    fn buffers_future_segment_and_flushes_when_gap_filled() {
        let mut assembler = TcpAssembler::new();
        let _ = assembler.push(0, b"hello");
        assert!(matches!(assembler.push(10, b"!"), AssemblerResult::Pending));
        assert_eq!(
            assembler.push(5, b"world"),
            AssemblerResult::Advanced(AssembledChunk {
                bytes: b"world!".to_vec(),
                fin: false,
                rst: false,
            })
        );
    }

    #[test]
    fn ignores_retransmit_but_rejects_conflicting_overlap() {
        let mut assembler = TcpAssembler::new();
        let _ = assembler.push(0, b"hello");
        assert!(matches!(
            assembler.push(0, b"hello"),
            AssemblerResult::Pending
        ));
        assert!(matches!(
            assembler.push(2, b"xxllo"),
            AssemblerResult::ConflictDetected
        ));
    }

    #[test]
    fn preserves_fin_and_rst_flags() {
        let mut assembler = TcpAssembler::new();
        let _ = assembler.push(0, b"hello");
        assert_eq!(
            assembler.push_segment(5, b"!", true, false),
            AssemblerResult::Advanced(AssembledChunk {
                bytes: b"!".to_vec(),
                fin: true,
                rst: false,
            })
        );
        assert_eq!(
            assembler.push_segment(6, b"", false, true),
            AssemblerResult::Advanced(AssembledChunk {
                bytes: Vec::new(),
                fin: false,
                rst: true,
            })
        );
    }

    #[test]
    fn marks_gap_on_finish() {
        let mut assembler = TcpAssembler::new();
        let _ = assembler.push(0, b"hello");
        assert!(matches!(
            assembler.push(10, b"tail"),
            AssemblerResult::Pending
        ));
        assert!(matches!(assembler.finish(), AssemblerResult::GapDetected));
    }
}
