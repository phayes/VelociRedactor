use std::sync::LazyLock;

use regex::Regex;

use super::{Detection, Detector, LeafContext};

/// Candidate tokens. `/` is excluded so whole file paths are not treated as a
/// single token; high-entropy path segments are still found individually.
static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9+_=-]{10,}").unwrap());

/// Flags long alphanumeric tokens whose Shannon entropy exceeds a threshold.
///
/// The default threshold of 4.5 bits per byte is high enough to skip ordinary
/// words and identifiers while catching typical API keys and tokens, which
/// usually score above 5.
#[derive(Debug, Clone, Copy)]
pub struct EntropyDetector {
    threshold: f64,
}

impl EntropyDetector {
    pub const DEFAULT_THRESHOLD: f64 = 4.5;

    pub fn new(threshold: f64) -> Self {
        Self { threshold }
    }

    pub fn threshold(&self) -> f64 {
        self.threshold
    }
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self::new(Self::DEFAULT_THRESHOLD)
    }
}

impl Detector for EntropyDetector {
    fn name(&self) -> &str {
        "entropy"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for m in TOKEN.find_iter(value) {
            if shannon_entropy(m.as_str().as_bytes()) > self.threshold {
                out.push(Detection::new(m.range(), self.name()));
            }
        }
    }
}

/// Shannon entropy of `bytes`, in bits per byte.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(s: &str) -> Vec<&str> {
        let mut out = Vec::new();
        EntropyDetector::default().detect(s, &LeafContext::default(), &mut out);
        out.iter().map(|d| &s[d.range.clone()]).collect()
    }

    #[test]
    fn entropy_values() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        assert!((shannon_entropy(b"ab") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn flags_high_entropy_tokens() {
        assert_eq!(
            detect("my key is aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz ok"),
            ["aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz"]
        );
    }

    #[test]
    fn ignores_words_and_short_tokens() {
        assert!(detect("hello world, this is a normal sentence").is_empty());
        assert!(detect("abc123XYZ").is_empty());
    }

    #[test]
    fn file_paths_are_not_one_token() {
        assert!(detect("/usr/local/bin/some-program-name").is_empty());
        assert!(detect("src/components/controller/handler.go").is_empty());
    }
}
