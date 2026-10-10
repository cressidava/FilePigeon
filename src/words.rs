//! Word list for pairing codes. A code is `<nameplate>-<word>-<word>-<word>`.
//! Because pairing uses SPAKE2, an attacker gets exactly one online guess per
//! code (the server burns the nameplate on first join), so ~24 bits is plenty.


pub const WORDS: &[&str] = &[
    "acid", "acorn", "actor", "agent", "alarm", "album", "alley", "alpha", "amber", "anchor", "angle",
    "ankle", "apple", "apron", "arch", "arena", "arrow", "atlas", "atom", "attic", "autumn", "award",
    "bacon", "badge", "bagel", "baker", "bamboo", "banjo", "barn", "basin", "beach", "beacon", "bear",
    "berry", "bison", "blade", "blaze", "bloom", "board", "boat", "bolt", "bonus", "brain", "brass",
    "bread", "brick", "bridge", "brook", "brush", "bubble", "bucket", "buffalo", "bugle", "cabin",
    "cactus", "camel", "canal", "candle", "canoe", "canyon", "cargo", "carpet", "castle", "cedar",
    "cello", "chalk", "cherry", "chess", "chimney", "cider", "cinema", "circle", "citrus", "clay",
    "cliff", "clock", "cloud", "clover", "cobalt", "cocoa", "comet", "coral", "cotton", "cougar",
    "crane", "crater", "crayon", "cricket", "crown", "crystal", "cube", "cypress", "daisy", "delta",
    "denim", "desert", "diamond", "dingo", "dolphin", "dragon", "drum", "dune", "eagle", "echo",
    "eclipse", "ember", "emerald", "engine", "falcon", "feather", "fern", "ferry", "fiddle", "fig",
    "flame", "flute", "forest", "fossil", "fox", "frost", "galaxy", "garden", "garlic", "gecko",
    "geyser", "ginger", "glacier", "globe", "goose", "granite", "grape", "gravel", "harbor", "hazel",
    "hammock", "harp", "hawk", "helmet", "hermit", "heron", "honey", "horizon", "iceberg", "igloo",
    "island", "ivory", "jacket", "jaguar", "jasmine", "jelly", "jungle", "kayak", "kernel", "kettle",
    "kiwi", "koala", "ladder", "lagoon", "lantern", "lava", "lemon", "lens", "lilac", "lily", "lion",
    "lizard", "lobster", "locket", "lotus", "magnet", "mango", "maple", "marble", "meadow", "melon",
    "meteor", "mint", "mirror", "monsoon", "moose", "mosaic", "moss", "nectar", "needle", "nickel",
    "noodle", "nugget", "oak", "oasis", "ocean", "olive", "onyx", "opal", "orbit", "orchid", "otter",
    "owl", "paddle", "panda", "panther", "paper", "parrot", "peach", "pearl", "pebble", "pelican",
    "pepper", "piano", "pigeon", "pine", "planet", "plum", "pollen", "pony", "poppy", "prairie",
    "prism", "puffin", "pumpkin", "quartz", "quill", "rabbit", "radar", "raven", "reef", "ribbon",
    "river", "robin", "rocket", "ruby", "saddle", "salmon", "sapphire", "satin", "sequoia", "shadow",
    "shell", "silver", "sketch", "sloth", "snow", "sparrow", "spruce", "squid", "summit", "sunset",
    "swan", "tango", "thistle", "thunder", "tiger", "timber", "topaz", "tulip", "tundra", "turtle",
    "umbrella", "valley", "velvet", "violet", "volcano", "walnut", "walrus", "willow", "zebra",
];

pub fn pick(n: usize) -> Vec<&'static str> {
    (0..n).map(|_| WORDS[uniform_index(WORDS.len())]).collect()
}

/// Uniform index in 0..len from OS randomness (rejection sampling avoids modulo bias).
fn uniform_index(len: usize) -> usize {
    let len = len as u32;
    let limit = u32::MAX - u32::MAX % len;
    loop {
        let mut b = [0u8; 4];
        crate::os_random(&mut b);
        let v = u32::from_le_bytes(b);
        if v < limit {
            return (v % len) as usize;
        }
    }
}

pub fn is_word(w: &str) -> bool {
    WORDS.contains(&w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn words_are_unique_and_plentiful() {
        let set: HashSet<_> = WORDS.iter().collect();
        assert_eq!(set.len(), WORDS.len(), "duplicate words");
        assert!(WORDS.len() >= 256, "only {} words", WORDS.len());
    }
}
