use std::{collections::BTreeMap, time::Duration};

use crate::{Error, Latency};

const PRECISION_BITS: u32 = 4;
const STRIDE: usize = 1 << PRECISION_BITS;
const BUCKETS: usize = (65 - PRECISION_BITS as usize) * STRIDE;

// The first 32 buckets count exact nanoseconds; each following octave
// divides into 16 buckets. Report the upper bound of the percentile bucket.

pub(crate) struct Histogram {
    bins: [u64; BUCKETS],
    count: u64,
    max: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            bins: [0; BUCKETS],
            count: 0,
            max: 0,
        }
    }
}

impl Histogram {
    pub(crate) fn record(&mut self, elapsed: Duration) {
        let ns = nanos(elapsed);
        let shift = ns
            .checked_ilog2()
            .unwrap_or(0)
            .saturating_sub(PRECISION_BITS);
        self.bins[shift as usize * STRIDE + (ns >> shift) as usize] += 1;
        self.count += 1;
        self.max = self.max.max(ns);
    }

    pub(crate) fn merge(&mut self, other: &Self) {
        for (bin, &count) in self.bins.iter_mut().zip(&other.bins) {
            *bin += count;
        }
        self.count += other.count;
        self.max = self.max.max(other.max);
    }

    pub(crate) fn summary(&self) -> Latency {
        if self.count == 0 {
            return Latency::default();
        }
        let mut quantiles = [0; 3];
        let targets = [50, 95, 99].map(|q| (u128::from(self.count) * q).div_ceil(100) as u64);
        let mut next = 0;
        let mut cumulative = 0;
        for (index, &count) in self.bins.iter().enumerate() {
            cumulative += count;
            while next < targets.len() && cumulative >= targets[next] {
                let shift = (index / STRIDE).saturating_sub(1);
                let width = 1u64 << shift;
                let start = ((index - shift * STRIDE) as u64) << shift;
                quantiles[next] = (start | (width - 1)).min(self.max);
                next += 1;
            }
            if next == targets.len() {
                break;
            }
        }
        let [p50, p95, p99] = quantiles;
        Latency {
            samples: self.count,
            p50_ns: Some(p50),
            p95_ns: Some(p95),
            p99_ns: Some(p99),
            max_ns: Some(self.max),
        }
    }
}

pub(crate) fn nanos(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

/// A contiguous prefix costs no storage. Past the first gap, a 64-bit block
/// represents any subset of 64 IDs even if arrivals alternate or are reordered.
#[derive(Default)]
pub(crate) struct SequenceSet {
    next: u64,
    gaps: BTreeMap<u64, u64>,
}

impl SequenceSet {
    pub(crate) fn insert(&mut self, seq: u64) -> bool {
        if seq < self.next {
            return false;
        }
        if seq == self.next {
            self.next += 1;
            if self.next.is_multiple_of(64) {
                self.gaps.remove(&(seq / 64));
            }
            while let Some((&block, &bits)) = self.gaps.first_key_value() {
                if block != self.next / 64 {
                    break;
                }
                let offset = self.next % 64;
                let advance = (bits >> offset).trailing_ones() as u64;
                self.next += advance;
                if offset + advance != 64 {
                    if bits >> (offset + advance) == 0 {
                        self.gaps.pop_first();
                    }
                    break;
                }
                self.gaps.pop_first();
            }
            return true;
        }
        let bits = self.gaps.entry(seq / 64).or_default();
        let flag = 1 << (seq % 64);
        let is_new = *bits & flag == 0;
        *bits |= flag;
        is_new
    }

    pub(crate) fn verify(&self, published: u64) -> Result<(), Error> {
        let past_end = self.gaps.last_key_value().is_some_and(|(&block, &bits)| {
            block * 64 + u64::from(63 - bits.leading_zeros()) >= published
        });
        if self.next > published || past_end {
            return Err(Error::Protocol("received a sequence that wasn't published"));
        }
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct Deliveries {
    pub(crate) unique: u64,
    pub(crate) duplicates: u64,
    pub(crate) late: u64,
    pub(crate) latency: Histogram,
}

impl Deliveries {
    pub(crate) fn record(&mut self, new: bool, late: bool, elapsed: Duration) {
        if new {
            self.unique += 1;
            self.late += u64::from(late);
            self.latency.record(elapsed);
        } else {
            self.duplicates += 1;
        }
    }

    pub(crate) fn merge(&mut self, other: &Self) {
        self.unique += other.unique;
        self.duplicates += other.duplicates;
        self.late += other.late;
        self.latency.merge(&other.latency);
    }

    pub(crate) fn loss(&self, expected: u64) -> Result<u64, Error> {
        expected
            .checked_sub(self.unique)
            .ok_or(Error::Protocol("more unique deliveries than expected"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holes_and_reordering_are_not_duplicates_or_extra_deliveries() {
        let mut seen = SequenceSet::default();
        let mut deliveries = Deliveries::default();
        for seq in [3, 2, 2, 0, 3, 4] {
            deliveries.record(seen.insert(seq), seq == 4, Duration::from_nanos(seq));
        }
        assert_eq!(deliveries.loss(5).unwrap(), 1);
        assert_eq!(deliveries.duplicates, 2);
        assert_eq!(deliveries.late, 1);
        assert_eq!(deliveries.latency.summary().samples, 4);
        assert!(seen.verify(5).is_ok());
        assert!(seen.verify(4).is_err());
        assert!(seen.insert(1));
        assert!(seen.gaps.is_empty());
        assert_eq!(seen.next, 5);
    }

    #[test]
    fn out_of_order_blocks_compact_across_word_boundaries() {
        let mut seen = SequenceSet::default();
        for index in (0..130).rev() {
            assert!(seen.insert(index));
            assert!(!seen.insert(index));
        }
        assert!(seen.gaps.is_empty());
        assert_eq!(seen.next, 130);
        assert!(seen.verify(130).is_ok());
    }

    #[test]
    fn histogram_merges_counts_and_returns_nearest_rank_bucket_bounds() {
        let mut a = Histogram::default();
        let mut b = Histogram::default();
        assert_eq!(a.summary().p99_ns, None);
        for i in 1..=100 {
            if i % 2 == 0 { &mut a } else { &mut b }.record(Duration::from_nanos(i));
        }
        a.merge(&b);
        let out = a.summary();
        assert_eq!(out.samples, 100);
        assert_eq!(out.p50_ns, Some(51));
        assert_eq!(out.p95_ns, Some(95));
        assert_eq!(out.p99_ns, Some(99));
        assert_eq!(out.max_ns, Some(100));
    }
}
