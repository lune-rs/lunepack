#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    lunepack_codec_lzma::fuzz::patch(data);
});
