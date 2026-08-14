//! Code points in and out of CPython.
//!
//! The engine's source is a `&[u32]` of code points (see
//! `abnf_core::Src`), and Python hands us a `str`.  This module is the
//! only place that converts between the two.
//!
//! **In** — [`CodePoints`] widens a `str` with `PyUnicode_AsUCS4`.
//! The buffer comes from a small thread-local pool rather than a fresh
//! allocation per parse, and is returned on drop.  A pool rather than
//! one buffer because parses nest: an embedded Python parser
//! (`PyCallbackParser`) can call back in and start another parse while
//! the outer one is still holding its source, and an exclusion
//! sub-parse runs inside its parent.  Each active parse holds its own
//! buffer; the pool just avoids re-allocating for the common case
//! where they come and go one at a time.
//!
//! **Out** — [`substring`] slices the caller's own `str` object, which
//! is how node values are produced: a node's value is always a
//! contiguous span of the source, so no text needs to be rebuilt.
//! [`from_code_points`] is the fallback for the one case with no
//! original object to slice: handing a sub-slice to an embedded Python
//! parser.
//!
//! Every function here works for lone surrogates, which is the point
//! (issue #173).  `PyUnicode_AsUCS4`, `PyUnicode_Substring` and
//! `PyUnicode_DecodeUTF32` are all in the limited API, so none of this
//! costs us the abi3 build.

use std::cell::RefCell;
use std::os::raw::c_char;

use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::PyString;

thread_local! {
    /// Buffers available for reuse.  Bounded so a deeply nested parse
    /// that unwinds cannot leave an unbounded amount of memory parked
    /// here for the life of the thread.
    static POOL: RefCell<Vec<Vec<u32>>> = const { RefCell::new(Vec::new()) };
}

const POOL_LIMIT: usize = 8;

/// A `str`'s code points, in a buffer borrowed from the thread-local
/// pool and returned to it on drop.
pub struct CodePoints {
    buf: Vec<u32>,
}

impl CodePoints {
    /// Widen `s` to code points.
    pub fn new(s: &Bound<'_, PyString>) -> PyResult<Self> {
        let py = s.py();
        let ptr = s.as_ptr();
        // `PyUnicode_GetLength` is the code-point length, which is
        // exactly the unit the engine indexes by.
        let len = unsafe { ffi::PyUnicode_GetLength(ptr) };
        if len < 0 {
            return Err(PyErr::fetch(py));
        }
        let len = len as usize;

        let mut buf = POOL.with(|p| p.borrow_mut().pop()).unwrap_or_default();
        buf.clear();
        buf.reserve(len);
        if len > 0 {
            // SAFETY: `buf` has capacity for at least `len` elements,
            // and `PyUnicode_AsUCS4` writes exactly `len` of them when
            // it succeeds (`copy_null = 0`, so no trailing NUL is
            // written and none is accounted for above).  `set_len` runs
            // only on the success path, so no uninitialised element is
            // ever observable.
            let written = unsafe {
                ffi::PyUnicode_AsUCS4(
                    ptr,
                    buf.spare_capacity_mut().as_mut_ptr().cast::<ffi::Py_UCS4>(),
                    len as ffi::Py_ssize_t,
                    0,
                )
            };
            if written.is_null() {
                POOL.with(|p| {
                    let mut pool = p.borrow_mut();
                    if pool.len() < POOL_LIMIT {
                        pool.push(buf);
                    }
                });
                return Err(PyErr::fetch(py));
            }
            unsafe { buf.set_len(len) };
        }
        Ok(Self { buf })
    }

    pub fn as_slice(&self) -> &[u32] {
        &self.buf
    }
}

impl Drop for CodePoints {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.buf);
        POOL.with(|p| {
            let mut pool = p.borrow_mut();
            if pool.len() < POOL_LIMIT {
                pool.push(buf);
            }
        });
    }
}

/// `source[start:end]` by code point, as Python would slice it.
///
/// This is how every node value is produced.  Slicing the caller's own
/// object means the text is never re-encoded, so a value containing a
/// lone surrogate survives the round trip unchanged.
pub fn substring<'py>(
    source: &Bound<'py, PyString>,
    start: usize,
    end: usize,
) -> PyResult<Bound<'py, PyString>> {
    let py = source.py();
    let obj = unsafe {
        ffi::PyUnicode_Substring(
            source.as_ptr(),
            start as ffi::Py_ssize_t,
            end as ffi::Py_ssize_t,
        )
    };
    if obj.is_null() {
        return Err(PyErr::fetch(py));
    }
    // SAFETY: `PyUnicode_Substring` returns a new reference to a `str`
    // on success, which is exactly what `from_owned_ptr` expects.
    Ok(unsafe { Bound::from_owned_ptr(py, obj) }.cast_into::<PyString>()?)
}

/// Build a `str` from code points.
///
/// Only for the case with no source object to slice: passing a
/// sub-slice of the source to an embedded Python parser.  Goes via
/// UTF-32 with `surrogatepass`, the one limited-API decoder that
/// round-trips lone surrogates; the byte order is stated explicitly so
/// no leading U+FEFF is mistaken for a BOM and swallowed.
pub fn from_code_points<'py>(py: Python<'py>, cps: &[u32]) -> PyResult<Bound<'py, PyString>> {
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(cps.as_ptr().cast::<u8>(), std::mem::size_of_val(cps))
    };
    let mut byteorder: i32 = if cfg!(target_endian = "little") { -1 } else { 1 };
    let errors = c"surrogatepass";
    let obj = unsafe {
        ffi::PyUnicode_DecodeUTF32(
            bytes.as_ptr().cast::<c_char>(),
            bytes.len() as ffi::Py_ssize_t,
            errors.as_ptr(),
            &mut byteorder,
        )
    };
    if obj.is_null() {
        return Err(PyErr::fetch(py));
    }
    // SAFETY: a successful `PyUnicode_DecodeUTF32` returns a new
    // reference to a `str`.
    Ok(unsafe { Bound::from_owned_ptr(py, obj) }.cast_into::<PyString>()?)
}
