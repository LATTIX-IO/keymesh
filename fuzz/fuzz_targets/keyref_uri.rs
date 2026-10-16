#![no_main]

// FOSS-402 fuzzing target: untrusted bytes must never panic or acquire
// noncanonical textual representation. This harness is not a credential vault.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(input) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(parsed) = input.parse::<keymesh::KeyRef>() {
        let canonical = parsed.to_string();
        assert_eq!(input, canonical);
        let reparsed: keymesh::KeyRef = canonical.parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(parsed, reparsed);
    }
});
