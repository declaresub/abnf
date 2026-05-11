//! Pure-Rust ABNF parser engine.
//!
//! No Python dependency.  The PyO3 bindings in the sibling
//! `abnf-rust-ext` crate adapt this crate's API to Python; the engine
//! itself is consumable from any Rust caller.
//!
//! Implementation lands in subsequent phases; this crate is currently a
//! placeholder so the workspace and the wheel build cleanly.

#![deny(unsafe_op_in_unsafe_fn)]
