//! Safety net: guarantees a full `restore` runs even if the user hits
//! Ctrl+C, something sends SIGTERM, or (with `--timeout`) a fixed time
//! limit expires while network changes are active.
//!
//! Signals are handled the "synchronous" way instead of with an async
//! signal handler: SIGINT/SIGTERM are blocked (`pthread_sigmask`) in every
//! thread of the process, and a dedicated thread blocks on `sigwait` for
//! them. That thread therefore runs in ordinary thread context — not
//! inside a signal handler — so it's safe for it to do real work (take the
//! state lock, run `disable()`, print messages). Doing any of that from an
//! actual signal handler would be undefined behavior.

use crate::i18n::{Lang, tr};
use std::sync::mpsc;
use std::time::Duration;

pub enum Trip {
    Signal,
    Timeout,
}

/// Arms the watchdog. Call once, early in `main()`, before enabling any
/// module. Blocks SIGINT/SIGTERM process-wide and spawns the threads that
/// wait for either of them or for `timeout` to elapse. When one fires,
/// `on_trip` runs (once) on a background thread; it should perform a full
/// restore and must not panic — nothing catches it if it does.
pub fn arm(lang: Lang, timeout: Option<Duration>, on_trip: impl FnOnce(Trip) + Send + 'static) {
    // SAFETY: an all-zero `sigset_t` is a valid empty signal set, and the
    // `sigemptyset`/`sigaddset`/`pthread_sigmask` calls operate on that local
    // set with valid pointers for the duration of the block.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGINT);
        libc::sigaddset(&raw mut set, libc::SIGTERM);
        // Block in this thread; new threads inherit the mask, so this
        // covers the whole process from here on.
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
    }

    let (tx, rx) = mpsc::channel::<Trip>();

    let tx_sig = tx.clone();
    std::thread::spawn(move || {
        // SAFETY: an all-zero `sigset_t` is a valid empty set; this thread
        // blocks on `sigwait` with valid pointers to local storage.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut sig: i32 = 0;
        unsafe {
            libc::sigemptyset(&raw mut set);
            libc::sigaddset(&raw mut set, libc::SIGINT);
            libc::sigaddset(&raw mut set, libc::SIGTERM);
            libc::sigwait(&raw const set, &raw mut sig);
        }
        let _ = tx_sig.send(Trip::Signal);
    });

    if let Some(d) = timeout {
        let tx_timeout = tx;
        std::thread::spawn(move || {
            std::thread::sleep(d);
            let _ = tx_timeout.send(Trip::Timeout);
        });
    }

    eprintln!(
        "{}",
        tr(
            lang,
            "[i] safety net armed: Ctrl+C or SIGTERM triggers a full restore",
            "[i] red de seguridad activa: Ctrl+C o SIGTERM disparan un restore completo",
        )
    );
    if let Some(d) = timeout {
        eprintln!(
            "[i] {} {}s",
            tr(
                lang,
                "auto-restore scheduled in",
                "auto-restore programado en"
            ),
            d.as_secs()
        );
    }

    std::thread::spawn(move || {
        if let Ok(trip) = rx.recv() {
            on_trip(trip);
        }
    });
}
