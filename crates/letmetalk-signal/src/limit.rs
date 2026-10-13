use std::collections::HashMap;
use std::hash::Hash;
use std::time::Instant;

#[derive(Clone, Copy)]
pub struct Rate {
    pub per_sec: f64,
    pub burst: f64,
}

#[derive(Clone, Copy)]
pub struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    pub fn new(rate: Rate, now: Instant) -> Self {
        Self {
            tokens: rate.burst,
            at: now,
        }
    }

    fn refilled(&self, rate: Rate, now: Instant) -> f64 {
        let added = now.duration_since(self.at).as_secs_f64() * rate.per_sec;
        (self.tokens + added).min(rate.burst)
    }

    pub fn take(&mut self, rate: Rate, now: Instant) -> bool {
        self.tokens = self.refilled(rate, now);
        self.at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

/// Takes one token from `key`'s bucket. A new key first drops the buckets that have refilled, since a full bucket
/// is the same as a new one, so the map holds only keys that are still spending.
pub fn take_keyed<K: Hash + Eq>(
    buckets: &mut HashMap<K, Bucket>,
    key: K,
    rate: Rate,
    now: Instant,
) -> bool {
    if !buckets.contains_key(&key) {
        buckets.retain(|_, bucket| bucket.refilled(rate, now) < rate.burst);
    }
    buckets
        .entry(key)
        .or_insert_with(|| Bucket::new(rate, now))
        .take(rate, now)
}
