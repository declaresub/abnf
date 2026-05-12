//! Byte ↔ code-point offset translation at the Python/Rust boundary.
//!
//! `abnf-core` indexes the source by UTF-8 byte; Python `str` is
//! indexed by code point.  The pure-Python backend has always exposed
//! `Match.start`, `ParseError.start`, and `LiteralNode.offset` as
//! code-point offsets, and user code (notably `Rule.parse_all`'s
//! `start < len(source)` check) relies on that contract.  Every value
//! crossing the FFI in either direction has to be translated here.
//!
//! ASCII source is the common case and skips the translation entirely
//! (`is_ascii()` is a vectorised byte scan that's effectively free
//! compared to a `chars().count()`).

/// Convert a byte offset within `source` to a code-point offset.
///
/// Out-of-bounds inputs saturate at the source's code-point length;
/// indices that land in the middle of a UTF-8 sequence are rounded
/// down to the start of that sequence (and counted as the code point
/// they belong to).
pub fn byte_to_cp(source: &str, byte_offset: usize) -> usize {
    if source.is_ascii() {
        return byte_offset.min(source.len());
    }
    if byte_offset == 0 {
        return 0;
    }
    if byte_offset >= source.len() {
        return source.chars().count();
    }
    // Slice up to the byte offset and count code points.  If the
    // offset is mid-sequence, back up to the previous char boundary.
    let mut adjusted = byte_offset;
    while adjusted > 0 && !source.is_char_boundary(adjusted) {
        adjusted -= 1;
    }
    source[..adjusted].chars().count()
}

/// Convert a code-point offset within `source` to a byte offset.
///
/// Saturates at the source's byte length when the requested code
/// point is past the end (matching Python's slice semantics).
pub fn cp_to_byte(source: &str, cp_offset: usize) -> usize {
    if source.is_ascii() {
        return cp_offset.min(source.len());
    }
    if cp_offset == 0 {
        return 0;
    }
    match source.char_indices().nth(cp_offset) {
        Some((byte_idx, _)) => byte_idx,
        None => source.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_is_identity() {
        let s = "hello world";
        assert_eq!(byte_to_cp(s, 0), 0);
        assert_eq!(byte_to_cp(s, 5), 5);
        assert_eq!(byte_to_cp(s, s.len()), s.len());
        assert_eq!(cp_to_byte(s, 0), 0);
        assert_eq!(cp_to_byte(s, 5), 5);
        assert_eq!(cp_to_byte(s, s.len()), s.len());
    }

    #[test]
    fn round_trips_through_two_byte_codepoints() {
        let s = "ééX"; // 3 code points, 5 UTF-8 bytes (2+2+1)
        // Code-point boundaries: 0, 1, 2, 3
        // Byte boundaries:       0, 2, 4, 5
        assert_eq!(byte_to_cp(s, 0), 0);
        assert_eq!(byte_to_cp(s, 2), 1);
        assert_eq!(byte_to_cp(s, 4), 2);
        assert_eq!(byte_to_cp(s, 5), 3);
        assert_eq!(cp_to_byte(s, 0), 0);
        assert_eq!(cp_to_byte(s, 1), 2);
        assert_eq!(cp_to_byte(s, 2), 4);
        assert_eq!(cp_to_byte(s, 3), 5);
    }

    #[test]
    fn out_of_bounds_saturates() {
        let s = "ab";
        assert_eq!(byte_to_cp(s, 999), 2);
        assert_eq!(cp_to_byte(s, 999), 2);
    }

    #[test]
    fn mid_utf8_byte_rounds_down() {
        let s = "é"; // 1 code point, 2 bytes
        // Byte 1 is mid-sequence; rounds down to code-point 0.
        assert_eq!(byte_to_cp(s, 1), 0);
    }
}
