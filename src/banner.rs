//! Startup banner.
//!
//! Hard rules (do not relax these without re-reading the module docs):
//!   1. Everything here writes to STDERR ONLY (`eprintln!`). STDOUT stays
//!      clean for structured/result output, so `anonify check | grep IP`
//!      and similar pipelines are never polluted by decorative output.
//!   2. The banner is suppressed automatically when stderr is not an
//!      interactive TTY (scripts, cron, `2>&1 | tee log`, CI). No flag is
//!      required for that — it just does the right thing.
//!   3. `--quiet` / `-q` suppresses it even on an interactive TTY.
//!   4. `NO_COLOR` (https://no-color.org/) set to any value disables ANSI
//!      color codes, falling back to plain text.
//!   5. Below 80 columns, a single-line compact banner is shown instead of
//!      the full ASCII art, so it doesn't wrap/break in narrow terminals,
//!      tmux panes, or tiling layouts.

use crate::i18n::{tr, Lang};
use std::io::IsTerminal;

const FULL_ART: &str = r"
                               ▀      ▄▀▀
  ▄▄▄   ▄ ▄▄    ▄▄▄   ▄ ▄▄   ▄▄▄    ▄▄█▄▄  ▄   ▄
 ▀   █  █▀  █  █▀ ▀█  █▀  █    █      █    ▀▄ ▄▀
 ▄▀▀▀█  █   █  █   █  █   █    █      █     █▄█
 ▀▄▄▀█  █   █  ▀█▄█▀  █   █  ▄▄█▄▄    █     ▀█
                                            ▄▀
                                           ▀▀";

const MIN_WIDTH_FOR_ART: usize = 80;

/// Decides whether the banner should be shown at all, given explicit
/// `--quiet`/`-q`. TTY detection is checked separately by the caller via
/// `stderr_is_tty()` so the decision is easy to unit test.
fn should_show(quiet: bool, stderr_is_tty: bool) -> bool {
    !quiet && stderr_is_tty
}

fn colors_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none()
}

fn terminal_width() -> usize {
    // Minimal, dependency-free column detection: respect $COLUMNS if the
    // shell exports it, otherwise query the kernel via TIOCGWINSZ on the
    // actual stderr fd. Falls back to 80 (i.e. "assume compact") if neither
    // is available, which is the safe default for an unknown environment.
    if let Some(cols) = std::env::var("COLUMNS").ok().and_then(|v| v.parse().ok()) {
        return cols;
    }

    #[repr(C)]
    struct WinSize {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
    }

    unsafe {
        let mut ws: WinSize = std::mem::zeroed();
        // TIOCGWINSZ = 0x5413 on Linux. STDERR_FILENO = 2.
        if libc::ioctl(2, 0x5413, &mut ws as *mut WinSize) == 0 && ws.ws_col > 0 {
            return ws.ws_col as usize;
        }
    }

    MIN_WIDTH_FOR_ART
}

/// Prints the startup banner to stderr if the current context calls for it.
/// Safe to call unconditionally at the top of `main()` — it no-ops for
/// non-interactive output, `--quiet`, and narrow terminals (compact form
/// instead).
pub fn show(lang: Lang, quiet: bool) {
    let stderr_is_tty = std::io::stderr().is_terminal();
    if !should_show(quiet, stderr_is_tty) {
        return;
    }

    let color = colors_enabled();
    let width = terminal_width();

    if width < MIN_WIDTH_FOR_ART {
        print_compact(lang, color);
    } else {
        print_full(lang, color);
    }
}

fn print_full(lang: Lang, color: bool) {
    let tagline = tr(
        lang,
        "reversible, memory-only network anonymity hardening",
        "hardening de anonimato en red, reversible y solo en memoria",
    );
    if color {
        eprintln!("\x1b[1;36m{FULL_ART}\x1b[0m");
        eprintln!("  \x1b[2m{tagline} — v{}\x1b[0m", env!("CARGO_PKG_VERSION"));
    } else {
        eprintln!("{FULL_ART}");
        eprintln!("  {tagline} — v{}", env!("CARGO_PKG_VERSION"));
    }
    eprintln!();
}

fn print_compact(lang: Lang, color: bool) {
    let line = tr(
        lang,
        "anonify — reversible network anonymity hardening",
        "anonify — hardening de anonimato en red, reversible",
    );
    if color {
        eprintln!("\x1b[1;36m{line}\x1b[0m v{}", env!("CARGO_PKG_VERSION"));
    } else {
        eprintln!("{line} v{}", env!("CARGO_PKG_VERSION"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_always_suppresses() {
        assert!(!should_show(true, true));
        assert!(!should_show(true, false));
    }

    #[test]
    fn non_tty_suppresses_without_a_flag() {
        assert!(!should_show(false, false));
    }

    #[test]
    fn interactive_and_not_quiet_shows() {
        assert!(should_show(false, true));
    }
}
