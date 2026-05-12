//! PyO3 bindings exposing the `abnf-core` engine to Python.
//!
//! The compiled module appears as ``abnf_rust._ext``; the Python
//! package wrapper in `src/abnf_rust/__init__.py` re-exports its
//! symbols.

// Replace the system allocator with mimalloc.  ABNF parsing
// produces many short-lived small allocations (per-Match node
// lists, per-Node children Vecs, Arc<str> for literal matches);
// mimalloc's segregated free-list design tends to beat
// system mallocs on this workload by a meaningful margin.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod bootstrap;
mod bridge;
mod errors;
mod external;
mod hooks;
mod iter;
mod nodes;
mod offset;
mod parsers;
mod recursion;

use pyo3::prelude::*;

#[pymodule]
fn _ext(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Custom panic hook that suppresses stderr noise for the
    // depth-exceeded panic emitted by `NamedRule::lparse`; the
    // PyO3 layer catches it and re-raises as `RecursionError`.
    recursion::install_panic_hook();

    // Combinators
    m.add_class::<parsers::PyAlternation>()?;
    m.add_class::<parsers::PyConcatenation>()?;
    m.add_class::<parsers::PyRepetition>()?;
    m.add_class::<parsers::PyOption>()?;
    m.add_class::<parsers::PyLiteral>()?;
    m.add_class::<parsers::PyProse>()?;
    m.add_class::<parsers::PyRepeat>()?;

    // Parse tree
    m.add_class::<nodes::PyMatch>()?;
    m.add_class::<nodes::PyNode>()?;
    m.add_class::<nodes::PyLiteralNode>()?;

    // Functions
    m.add_function(wrap_pyfunction!(bootstrap::bootstrap, m)?)?;
    m.add_function(wrap_pyfunction!(hooks::set_definition_hook, m)?)?;
    m.add_function(wrap_pyfunction!(bridge::clear_bridge, m)?)?;
    m.add_function(wrap_pyfunction!(bridge::bridge_size, m)?)?;

    Ok(())
}
