use std::cmp::min;
use std::fmt::Display;
use std::io::{self, Write};
use std::time::Instant;

#[derive(Debug, Clone, Copy)]
pub struct Progress {
    enabled: bool,
    total: usize,
    current: usize,
    start: Instant,
}

impl Progress {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            total: 1,
            current: 0,
            start: Instant::now(),
        }
    }

    pub fn set_total(&mut self, total: usize) {
        if self.enabled {
            self.total = total.max(1);
        }
    }

    pub fn stage(&mut self, name: &str) {
        self.stage_stats(name, "");
    }

    pub fn stage_stats(&mut self, name: &str, stats: impl Display) {
        if !self.enabled {
            return;
        }
        self.current = self.current.saturating_add(1);

        let done = self
            .current
            .saturating_mul(100)
            .checked_div(self.total)
            .unwrap_or(0);
        let done = min(done, 100);
        let left = 100 - done;
        let bar_width = 20usize;
        let filled = (done * bar_width) / 100;

        let bar = format!("[{}{}]", "#".repeat(filled), "-".repeat(bar_width - filled));
        let elapsed = self.start.elapsed();
        let elapsed_seconds = elapsed.as_secs();
        let maybe_stats = if stats.to_string().is_empty() {
            String::new()
        } else {
            format!(" | {stats}")
        };

        let speed = if self.current > 0 {
            elapsed_seconds / (self.current as u64)
        } else {
            0
        };

        eprintln!(
            "{} {}% done | {}% left | stage: {name} ({} of {}) | elapsed: {}s | avg {}s/stage{}",
            bar, done, left, self.current, self.total, elapsed_seconds, speed, maybe_stats,
        );
        let _ = io::stderr().flush();
    }
}
