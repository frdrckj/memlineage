#![no_main]

use libfuzzer_sys::fuzz_target;
use memlineage_core::Policy;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Policy::from_yaml(text);
});
