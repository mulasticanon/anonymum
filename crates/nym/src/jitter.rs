//! A random delay before the recipient's reverse-rendezvous callback (audit
//! MED-03, review H6). Without it the callback leaves the instant the
//! acceptance is final, so the timing links the chain event to the mixnet
//! traffic. A uniform delay, drawn fresh for every callback from the
//! operating system's randomness, blurs that link; it does not remove it
//! in a small population (unreviewed, and the range is a placeholder).

use std::time::Duration;

/// The range a callback delay is drawn from, inclusive, in milliseconds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CallbackJitter {
    min_ms: u64,
    max_ms: u64,
}

/// The longest delay accepted. The demo's stranger waits `SERVE_PATIENCE`
/// (600 s) for the call after coming back online; a longer delay plus the
/// call's own retries could outlast it.
pub const MAX_JITTER: Duration = Duration::from_secs(300);

impl CallbackJitter {
    /// The default: 30 to 300 seconds.
    pub const PRODUCTION: Self = CallbackJitter { min_ms: 30_000, max_ms: 300_000 };
    /// No delay, for fast local demo and end-to-end runs (`--no-jitter`).
    pub const NONE: Self = CallbackJitter { min_ms: 0, max_ms: 0 };

    /// A range `min..=max`, whole seconds, with `min <= max <= MAX_JITTER`.
    pub fn from_secs(min: u64, max: u64) -> Result<Self, String> {
        if min > max {
            return Err(format!("jitter {min}-{max}: the minimum is above the maximum"));
        }
        if max > MAX_JITTER.as_secs() {
            return Err(format!("jitter {min}-{max}: at most {} seconds", MAX_JITTER.as_secs()));
        }
        Ok(CallbackJitter { min_ms: min * 1_000, max_ms: max * 1_000 })
    }

    /// From the command line: `--no-jitter`, or `--jitter MIN-MAX` (seconds),
    /// or neither for [`Self::PRODUCTION`]. Both at once is an error.
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let none = args.iter().any(|a| a == "--no-jitter");
        let range = match args.iter().position(|a| a == "--jitter") {
            None => None,
            Some(i) => Some(args.get(i + 1).ok_or("--jitter needs MIN-MAX (seconds)")?),
        };
        match (none, range) {
            (true, Some(_)) => Err("--no-jitter and --jitter together".into()),
            (true, None) => Ok(Self::NONE),
            (false, None) => Ok(Self::PRODUCTION),
            (false, Some(text)) => {
                let (min, max) = text.split_once('-').ok_or(format!("--jitter {text}: expected MIN-MAX"))?;
                let parse = |s: &str| s.trim().parse::<u64>().map_err(|_| format!("--jitter {text}: not a number"));
                Self::from_secs(parse(min)?, parse(max)?)
            }
        }
    }

    pub fn min(&self) -> Duration {
        Duration::from_millis(self.min_ms)
    }

    pub fn max(&self) -> Duration {
        Duration::from_millis(self.max_ms)
    }

    /// A delay drawn uniformly from the range, using `next` as the source of
    /// uniform 64-bit values (rejection sampling, so no value is favoured).
    pub fn sample_with(&self, mut next: impl FnMut() -> u64) -> Duration {
        let span = self.max_ms - self.min_ms + 1;
        // 2^64 mod span: the values in that incomplete last block would
        // favour the low delays, so they are drawn again. What is accepted,
        // 0 ..= u64::MAX - rest, is a whole number of spans.
        let rest = (u64::MAX - span + 1) % span;
        loop {
            let value = next();
            if value <= u64::MAX - rest {
                return Duration::from_millis(self.min_ms + value % span);
            }
        }
    }

    /// A fresh delay from the operating system's randomness.
    pub fn sample(&self) -> Duration {
        self.sample_with(|| {
            let bytes = anonymum_crypto::random_bytes();
            u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_default_range_is_30_to_300_seconds() {
        assert_eq!(CallbackJitter::from_args(&args(&["callback", "--bob", "f"])), Ok(CallbackJitter::PRODUCTION));
        let p = CallbackJitter::PRODUCTION;
        assert_eq!((p.min(), p.max()), (Duration::from_secs(30), Duration::from_secs(300)));
    }

    #[test]
    fn samples_stay_inside_the_range_and_reach_both_ends() {
        let p = CallbackJitter::PRODUCTION;
        for _ in 0..2_000 {
            let d = p.sample();
            assert!(p.min() <= d && d <= p.max(), "{d:?}");
        }
        // The extremes of the source map to the ends of the range.
        assert_eq!(p.sample_with(|| 0), p.min());
        let span = 300_000 - 30_000 + 1;
        assert_eq!(p.sample_with(|| span - 1), p.max());
        assert_eq!(p.sample_with(|| span), p.min(), "wraps, it does not overflow the range");
    }

    #[test]
    fn values_that_would_favour_some_delays_are_drawn_again() {
        let p = CallbackJitter::PRODUCTION;
        // u64::MAX lies in the incomplete last block of the range, so it is
        // rejected and the next value is used.
        let mut values = [u64::MAX, 5].into_iter();
        assert_eq!(p.sample_with(|| values.next().unwrap()), p.min() + Duration::from_millis(5));
        // Fresh samples differ (the chance of 20 equal ones is negligible).
        let first = p.sample();
        assert!((0..20).any(|_| p.sample() != first));
    }

    #[test]
    fn zero_delay_mode_never_waits() {
        let none = CallbackJitter::from_args(&args(&["callback", "--no-jitter"])).unwrap();
        assert_eq!(none, CallbackJitter::NONE);
        for value in [0, 1, u64::MAX / 2, u64::MAX] {
            assert_eq!(none.sample_with(|| value), Duration::ZERO);
        }
        assert_eq!(none.sample(), Duration::ZERO);
    }

    #[test]
    fn custom_ranges_are_checked() {
        let fixed = CallbackJitter::from_args(&args(&["--jitter", "7-7"])).unwrap();
        assert_eq!(fixed.sample(), Duration::from_secs(7));
        assert_eq!(CallbackJitter::from_secs(0, 300).unwrap().max(), MAX_JITTER);
        assert!(CallbackJitter::from_secs(10, 9).is_err(), "minimum above maximum");
        assert!(CallbackJitter::from_secs(0, 301).is_err(), "longer than the limit");
        for bad in [&["--jitter"][..], &["--jitter", "5"], &["--jitter", "a-9"], &["--no-jitter", "--jitter", "1-2"]] {
            assert!(CallbackJitter::from_args(&args(bad)).is_err(), "{bad:?}");
        }
    }
}
