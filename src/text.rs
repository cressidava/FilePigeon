//! Making peer-supplied text safe to store and show.
//!
//! Names, file names and messages from other devices can carry characters that
//! lie about what they say: bidi overrides that reverse an extension
//! (`invoice` + U+202E + `fdp.exe` shows as `invoiceexe.pdf`), zero-width characters,
//! slash look-alikes, and terminal escape sequences. These helpers strip or
//! neutralise them.

/// Unicode format (Cf), line/paragraph separator and bidi-control characters.
/// Zero-width (non-)joiners U+200C/U+200D are deliberately *not* here: Persian,
/// Kurdish and Indic text and every multi-part emoji need them inside words.
pub fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890 | 0x0891 | 0x08E2 | 0x180E
        | 0x200B | 0x200E | 0x200F | 0x2028..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// Characters that look like a path separator but aren't one.
pub fn is_slash_lookalike(c: char) -> bool {
    matches!(c, '\u{2044}' | '\u{2215}' | '\u{2216}' | '\u{29F8}' | '\u{29F9}' | '\u{FE68}' | '\u{FF0F}' | '\u{FF3C}')
}

/// Anything that shouldn't appear in a name or file name shown to a person.
pub fn is_deceptive(c: char) -> bool {
    c.is_control() || is_invisible(c) || is_slash_lookalike(c)
}

/// Joiners are fine inside a word but have no business at either end.
pub fn has_dangling_joiner(s: &str) -> bool {
    let joiner = |c: char| matches!(c, '\u{200C}' | '\u{200D}');
    s.chars().next().is_some_and(joiner) || s.chars().last().is_some_and(joiner)
}

/// A device name as chosen by a peer: deceptive characters removed, whitespace
/// collapsed, at most 64 characters.
pub fn clean_name(name: &str) -> String {
    let filtered: String = name.chars().map(|c| if is_deceptive(c) { ' ' } else { c }).collect();
    filtered.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(64).collect()
}

/// Make any peer- or server-supplied string safe to print or log: control and
/// invisible characters become U+FFFD (so terminal escape sequences can't run)
/// and the result is capped at `max` characters.
pub fn display_safe(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i == max {
            out.push('…');
            break;
        }
        out.push(if c.is_control() || is_invisible(c) { '\u{FFFD}' } else { c });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_bidi_and_escapes() {
        assert_eq!(clean_name("  Bob\u{202E}\u{200B}  laptop\n "), "Bob laptop");
        assert_eq!(display_safe("a\u{1b}[2Jb\u{202E}c", 100), "a\u{FFFD}[2Jb\u{FFFD}c");
        assert_eq!(display_safe("abcdef", 3), "abc…");
        assert!(is_deceptive('\u{2215}'));
        assert!(!is_deceptive('é'));
        assert!(!is_deceptive('\u{200C}') && !is_deceptive('\u{200D}'), "joiners are legitimate");
        assert!(has_dangling_joiner("\u{200D}x") && !has_dangling_joiner("a\u{200D}b"));
    }
}
