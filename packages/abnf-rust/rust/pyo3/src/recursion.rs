//! FFI panic plumbing: propagate non-recoverable conditions from the
//! Rust core back to Python as catchable exceptions.
//!
//! The Rust core's `Parser::lparse` returns
//! `Result<MatchList, ParseError>`.  Two situations don't fit that
//! shape and need a side-channel:
//!
//! 1. **Depth-exceeded** in `NamedRule::lparse` — left-recursive
//!    grammars (`a = a "x" / "x"`) would otherwise SIGSEGV the
//!    process.  Returning `Err(ParseError)` is wrong: `Alternation`
//!    / `Repetition` swallow `ParseError` to drive backtracking,
//!    which would hide the grammar bug behind a silent successful
//!    parse.
//!
//! 2. **Non-`ParseError` Python exceptions** raised by a duck-typed
//!    parser (`PyCallbackParser`).  The pure-Python reference only
//!    catches `ParseError`; `TypeError`, `KeyError`,
//!    `KeyboardInterrupt`, etc. propagate uncaught.  The Rust core
//!    can't carry a `PyErr` through `ParseError` (which is purely
//!    Rust), so we stash the `PyErr` in a thread-local and panic.
//!
//! Both flows route through `call_lparse`, which runs the inner
//! `lparse` inside `catch_unwind` and converts the matching panic
//! tags into the right Python exception.  Other panics resume so
//! they keep surfacing as `PanicException` via PyO3's defaults.

use std::cell::RefCell;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;

use pyo3::exceptions::PyRecursionError;
use pyo3::prelude::*;

/// Substring identifying the depth-exceeded panic emitted by
/// `NamedRule::lparse`.  Kept narrow so the hook never silences
/// unrelated panics that should remain visible.
const DEPTH_PANIC_TAG: &str = "maximum rule recursion depth exceeded";

/// Substring identifying the panic emitted when a `PyCallbackParser`
/// observed a non-`ParseError` Python exception.  The actual `PyErr`
/// is stored in `PENDING_PYERR`; the panic only acts as a control-
/// flow signal across the Rust core.
const PYERR_PANIC_TAG: &str = "pycallback-python-error";

thread_local! {
    /// Holds the most recent `PyErr` raised by a `PyCallbackParser`
    /// callback that should propagate (i.e. not a `ParseError`).
    /// Taken by `call_lparse` when it recognises the
    /// `PYERR_PANIC_TAG` panic.
    static PENDING_PYERR: RefCell<Option<PyErr>> = const { RefCell::new(None) };
}

static HOOK_INSTALLED: Once = Once::new();

/// Install the panic hook exactly once per process.
pub fn install_panic_hook() {
    HOOK_INSTALLED.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let message = info
                .payload()
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| info.payload().downcast_ref::<&'static str>().copied())
                .unwrap_or("");
            if message.contains(DEPTH_PANIC_TAG) || message.contains(PYERR_PANIC_TAG) {
                // Suppress the default hook's stderr output for these
                // specific panics — they're about to be caught and
                // re-raised as ordinary Python exceptions, so the
                // user sees one clean exception, not a panic banner
                // plus an exception.
                return;
            }
            previous(info);
        }));
    });
}

/// Stash a `PyErr` and unwind via panic so it can be re-raised at
/// the next `call_lparse` boundary.  Used by `PyCallbackParser` when
/// the Python callback raises something that isn't a `ParseError`.
pub fn propagate_pyerr(err: PyErr) -> ! {
    PENDING_PYERR.with(|cell| {
        *cell.borrow_mut() = Some(err);
    });
    panic!("{}", PYERR_PANIC_TAG);
}

/// Run a Rust `lparse`-style call inside `catch_unwind`, mapping a
/// depth-exceeded panic to a Python `RecursionError`, and a
/// PyCallbackParser-stash panic to the saved `PyErr`.  Any other
/// panic is re-raised so it surfaces normally via PyO3's
/// `PanicException`.
pub fn call_lparse<F>(f: F) -> PyResult<abnf_core::ParseResult>
where
    F: FnOnce() -> abnf_core::ParseResult,
{
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => Ok(result),
        Err(payload) => {
            let message = payload_message(&payload);
            if message.contains(DEPTH_PANIC_TAG) {
                Err(PyRecursionError::new_err(message))
            } else if message.contains(PYERR_PANIC_TAG) {
                let err = PENDING_PYERR.with(|cell| cell.borrow_mut().take());
                Err(err.unwrap_or_else(|| {
                    pyo3::exceptions::PyRuntimeError::new_err(
                        "PyCallbackParser stash empty",
                    )
                }))
            } else {
                panic::resume_unwind(payload)
            }
        }
    }
}

fn payload_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else {
        "rust panic".to_string()
    }
}
