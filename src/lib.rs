use digest;

use digest::generic_array::typenum::U64;
use digest::generic_array::GenericArray;
use digest::{Reset, Digest, FixedOutput, Input};
use sha2::Sha256;

pub const BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Computes a hash using the same algorithm that the Dropbox API uses for the
/// the "content_hash" metadata field.
///
/// Implements the `digest::Digest` trait, whose `result()` function returns a
/// raw binary representation of the hash.  The "content_hash" field in the
/// Dropbox API is a hexadecimal-encoded version of this value.
///
/// Example:
///
/// ```
/// extern crate digest;
/// use dropbox_content_hasher::DropboxContentHasher;
/// use std::io::Read;
/// use digest::{Digest,Input,FixedOutput};
///
/// let mut hasher = DropboxContentHasher::new();
/// let mut buf: [u8; 4096] = [0; 4096];
/// let mut f = std::fs::File::open("src/lib.rs").unwrap();
/// loop {
///     let len = f.read(&mut buf).unwrap();
///     if len == 0 { break; }
///     Input::input(&mut hasher, &buf[..len])
/// }
/// drop(f);
///
/// let hex_hash = format!("{:x}", hasher.result());
/// println!("{}", hex_hash);
/// ```

#[derive(Clone, Debug)]
pub struct DropboxContentHasher {
    overall_hasher: Sha256,
    block_hasher: Sha256,
    block_pos: usize,
}

impl DropboxContentHasher {
    pub fn new() -> Self {
        DropboxContentHasher {
            overall_hasher: Sha256::new(),
            block_hasher: Sha256::new(),
            block_pos: 0,
        }
    }
}

impl Default for DropboxContentHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Reset for DropboxContentHasher {
    fn reset(&mut self) {
        self.overall_hasher = Sha256::new();
        self.block_hasher = Sha256::new();
        self.block_pos = 0;
    }
}

impl Input for DropboxContentHasher {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        let mut input = data.as_ref();
        while input.len() > 0 {
            if self.block_pos == BLOCK_SIZE {
                let block_hasher = self.block_hasher.clone();
                Input::input(&mut self.overall_hasher, block_hasher.result().as_slice());
                self.block_hasher = Sha256::new();
                self.block_pos = 0;
            }

            let space_in_block = BLOCK_SIZE - self.block_pos;
            let (head, rest) = input.split_at(::std::cmp::min(input.len(), space_in_block));
            Input::input(&mut self.block_hasher, head);

            self.block_pos += head.len();
            input = rest;
        }
    }
}

impl FixedOutput for DropboxContentHasher {
    type OutputSize = <Sha256 as FixedOutput>::OutputSize;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        if self.block_pos > 0 {
            Input::input(&mut self.overall_hasher, self.block_hasher.result().as_slice());
        }
        self.overall_hasher.result()
    }
}

impl digest::BlockInput for DropboxContentHasher {
    type BlockSize = U64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_vector() {
        let expected = "485291fa0ee50c016982abbfa943957bcd231aae0492ccbaa22c58e3997b35e0".to_string();
        let mut file = File::open("test-data/milky-way-nasa.jpg").expect("Couldn't open test file");

        let mut hasher = DropboxContentHasher::new();
        let mut buf: [u8; 4096] = [0; 4096];
        loop {
            let len = file.read(&mut buf).unwrap();
            if len == 0 { break; }
            Input::input(&mut hasher, &buf[..len])
        }
        drop(file);

        let hex_hash = format!("{:x}", hasher.result());
        assert_eq!(hex_hash, expected);
    }
}
