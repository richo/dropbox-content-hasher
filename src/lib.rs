#![deny(unused_must_use, missing_debug_implementations)]
#![warn(rust_2018_idioms)]

use digest;

use digest::generic_array::typenum::U64;
use digest::generic_array::GenericArray;
use digest::{Reset, Digest, FixedOutput, Input};
use sha2::Sha256;

use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Computes a hash using the same algorithm that the Dropbox API uses for the
/// the "content_hash" metadata field.
///
/// Implements the `digest::Digest` trait, whose `result()` function returns a
/// raw binary representation of the hash.  The "content_hash" field in the
/// Dropbox API is a hexadecimal-encoded version of this value.
///
/// For examples see `hash_file` and `hash_reader`, for an using this object directly see the
/// source of `hash_reader`.

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

    /// Return the content_hash for a given file, or an io::Error from either opening or reading
    /// the file.
    ///
    /// ```
    /// extern crate digest;
    /// use dropbox_content_hasher::DropboxContentHasher;
    /// use std::path::PathBuf;
    ///
    /// let path = PathBuf::from("src/lib.rs");
    ///
    /// let hex_hash = format!("{:x}", DropboxContentHasher::hash_file(&path).unwrap());
    /// println!("{}", hex_hash);
    /// ```
    pub fn hash_file<T>(path: T) -> std::io::Result<GenericArray<u8, <Self as FixedOutput>::OutputSize>>
    where T: AsRef<Path> {
        let file = File::open(&path)?;
        return DropboxContentHasher::hash_reader(&file);
    }

    /// Return the content_hash for a given object implementing Read, or an io::Error resulting
    /// from trying to read its contents.
    ///
    /// ```
    /// extern crate digest;
    /// use dropbox_content_hasher::DropboxContentHasher;
    ///
    /// let mut f = std::fs::File::open("src/lib.rs").unwrap();
    ///
    /// let hex_hash = format!("{:x}", DropboxContentHasher::hash_reader(&mut f).unwrap());
    /// println!("{}", hex_hash);
    /// ```
    pub fn hash_reader<T>(mut reader: T) -> std::io::Result<GenericArray<u8, <Self as FixedOutput>::OutputSize>>
    where T: Read {
        let mut hasher = DropboxContentHasher::new();
        let mut buf = vec![0; BLOCK_SIZE];
        loop {
            let len = reader.read(&mut buf)?;
            if len == 0 { break; }
            Input::input(&mut hasher, &buf[..len])
        }
        Ok(hasher.result())
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

    #[test]
    fn test_vector() {
        let expected = "485291fa0ee50c016982abbfa943957bcd231aae0492ccbaa22c58e3997b35e0".to_string();
        let mut file = File::open("test-data/milky-way-nasa.jpg").expect("Couldn't open test file");

        let result = DropboxContentHasher::hash_reader(&mut file).expect("Couldn't hash test file");

        let hex_hash = format!("{:x}", result);
        assert_eq!(hex_hash, expected);
    }
}
