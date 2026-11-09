// Does the real macOS system libcompression LZFSE decoder (COMPRESSION_LZFSE,
// the one decmpfs actually uses) accept bytes CrushLZFSE produces? If not,
// reusing Algo::Lzfse's on-disk type for a CrushLZFSE-encoded chunk would
// write files the OS can't read back.
use std::os::raw::c_void;

#[link(name = "compression")]
unsafe extern "C" {
    fn compression_decode_buffer(
        dst_buffer: *mut u8,
        dst_size: usize,
        src_buffer: *const u8,
        src_size: usize,
        scratch_buffer: *mut c_void,
        algorithm: u32,
    ) -> usize;
}

const COMPRESSION_LZFSE: u32 = 0x801;

fn sample(n: usize) -> Vec<u8> {
    b"The quick brown fox jumps over the lazy dog. ".iter().copied().cycle().take(n).collect()
}

#[test]
fn crushlzfse_output_decodes_via_system_libcompression() {
    let data = sample(65536);
    let mut scratch = crushlzfse::Scratch::new();
    for level in crushlzfse::Level::MIN.0..=crushlzfse::Level::MAX.0 {
        let (params, _) = crushlzfse::Params::for_level(crushlzfse::Level(level));
        let mut compressed = vec![0u8; crushlzfse::compress_bound(data.len(), &params)];
        let n = crushlzfse::compress_into_with(&mut compressed, &data, &params, &mut scratch)
            .expect("crushlzfse encode");
        compressed.truncate(n);
        let mut back = vec![0u8; data.len()];
        let written = unsafe {
            compression_decode_buffer(
                back.as_mut_ptr(),
                back.len(),
                compressed.as_ptr(),
                compressed.len(),
                std::ptr::null_mut(),
                COMPRESSION_LZFSE,
            )
        };
        assert_eq!(written, data.len(), "level {level}: system libcompression decoded a different length");
        assert_eq!(back, data, "level {level}: system libcompression decoded different bytes");
    }
}

#[test]
fn system_libcompression_output_decodes_via_crushlzfse() {
    // Inverse direction: confirms the bitstream matches both ways, not just
    // that the system decoder accepts crushlzfse's output.
    #[link(name = "compression")]
    unsafe extern "C" {
        fn compression_encode_buffer(
            dst_buffer: *mut u8,
            dst_size: usize,
            src_buffer: *const u8,
            src_size: usize,
            scratch_buffer: *mut c_void,
            algorithm: u32,
        ) -> usize;
    }

    let data = sample(65536);
    let mut dst = vec![0u8; data.len()];
    let written = unsafe {
        compression_encode_buffer(dst.as_mut_ptr(), dst.len(), data.as_ptr(), data.len(), std::ptr::null_mut(), COMPRESSION_LZFSE)
    };
    assert!(written > 0, "system encoder should compress this input");
    dst.truncate(written);

    let mut back = vec![0u8; data.len()];
    let n = crushlzfse::decompress_into(&mut back, &dst).expect("crushlzfse decode of system-encoded bytes");
    assert_eq!(n, data.len());
    assert_eq!(back, data);
}
