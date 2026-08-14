//! Regression tests for issue #170: the rule-recursion guard has to
//! fire before the native stack runs out, not merely before a level
//! counter does.
//!
//! `MAX_RULE_RECURSION` alone counted levels while the resource being
//! protected was stack bytes.  A rule level costs ~3 KiB of native
//! stack, so 1000 levels wants ~3 MiB; on a stack smaller than that
//! the process died with no catchable error, which is exactly what
//! the guard existed to prevent.  Both tests below assert the guard
//! panics -- `catch_unwind` proves the process is still alive to
//! observe it, which a stack overflow would not allow.

use std::panic;
use std::sync::Arc;

use abnf_core::{Alternation, ArcParser, Concatenation, Literal, NamedRule, OptionParser, Parser};

/// The engine indexes by code point (issue #173), so tests build their
/// source the same way the PyO3 layer does.
fn cps(s: &str) -> Vec<u32> {
    s.chars().map(u32::from).collect()
}


/// `nested = "(" [ nested ] ")"` -- recursion driven by input depth.
fn nested_grammar() -> Arc<NamedRule> {
    let rule = Arc::new(NamedRule::new("nested"));
    let self_ref: ArcParser = Arc::new(Parser::from(rule.clone()));
    let inner: ArcParser = OptionParser::new(self_ref).into();
    let def: ArcParser = Concatenation::new(vec![
        Literal::string("(", false).into(),
        inner,
        Literal::string(")", false).into(),
    ])
    .into();
    rule.set_definition(def);
    rule
}

/// `a = a "x" / "x"` -- recursion with no input progress at all.
fn left_recursive_grammar() -> Arc<NamedRule> {
    let rule = Arc::new(NamedRule::new("a"));
    let self_ref: ArcParser = Arc::new(Parser::from(rule.clone()));
    let left: ArcParser =
        Concatenation::new(vec![self_ref, Literal::string("x", false).into()]).into();
    let def: ArcParser = Alternation::new(vec![left, Literal::string("x", false).into()]).into();
    rule.set_definition(def);
    rule
}

/// Run `f` with the panic hook silenced, returning the panic message
/// if it panicked.  The guard signals through a panic by design (see
/// `NamedRule::lparse`), so the hook's stderr banner is just noise
/// here.
fn panic_message(f: impl FnOnce() + panic::UnwindSafe) -> Option<String> {
    let previous = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(f);
    panic::set_hook(previous);
    result.err().map(|payload| {
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&'static str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

#[test]
fn deep_nesting_panics_instead_of_overflowing_the_stack() {
    let rule = nested_grammar();
    let depth = 5_000;
    let source = format!("{}{}", "(".repeat(depth), ")".repeat(depth));

    let message = panic_message(move || {
        let _ = rule.lparse(&cps(&source), 0);
    })
    .expect("deep nesting must trip the guard, not run to completion");

    // The PyO3 layer keys on this phrase to raise `RecursionError`.
    assert!(
        message.contains("maximum rule recursion depth exceeded"),
        "unexpected panic message: {message}"
    );
    // Depth 5000 is far past the byte budget but also past the level
    // count; the byte budget is the one that should fire first, since
    // it is reached in ~180 levels.
    assert!(
        message.contains("native stack budget"),
        "expected the stack-budget limit, got: {message}"
    );
}

#[test]
fn left_recursion_still_trips_the_level_counter() {
    let rule = left_recursive_grammar();

    let message = panic_message(move || {
        let src = cps("xxx");
        let _ = rule.lparse(&src, 0);
    })
    .expect("left recursion must trip the guard");

    assert!(
        message.contains("maximum rule recursion depth exceeded"),
        "unexpected panic message: {message}"
    );
}

#[test]
fn the_guard_resets_between_parses() {
    let rule = nested_grammar();
    let deep = format!("{}{}", "(".repeat(5_000), ")".repeat(5_000));

    // Blow the budget, unwind, then parse something trivial.  The
    // depth counter and the stack anchor are both restored by
    // `DepthGuard::drop` on the way out; if either leaked, this
    // second parse would fail or panic.
    let blown = rule.clone();
    let source = deep.clone();
    let _ = panic_message(move || {
        let _ = blown.lparse(&cps(&source), 0);
    });

    let src = cps("()");
    let matches = rule.lparse(&src, 0).expect("shallow parse after a blown budget");
    assert_eq!(matches[0].start, 2);
}
