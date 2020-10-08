use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use hex::encode;
use openssl::sha::sha256;

use crate::error::Error;
use crate::error::Error::{CorruptedStorage, HashCollision};

pub struct LocalStorage {
    root: PathBuf,
}

impl LocalStorage {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let root = PathBuf::from(path.as_ref());
        create_dir_all(root.join("keys"))?;
        create_dir_all(root.join("files"))?;
        Ok(Self { root })
    }

    pub fn set_key(&self, key: &[u8], username: &[u8]) -> Result<(), Error> {
        let hash = sha256(username);
        let filename = encode(hash);
        let p = self.root.join("keys").join(filename);
        if p.exists() {
            return Err(HashCollision);
        }
        let mut file = File::create(p)?;
        file.write_all(&(key.len() as u32).to_le_bytes())?;
        file.write_all(key)?;
        file.write_all(username)?;
        Ok(())
    }

    pub fn get_key(&self, user_hash: [u8; 32]) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
        let filename = encode(user_hash);
        let p = self.root.join("keys").join(filename);
        if !p.exists() {
            return Ok(None);
        }
        let mut file = File::open(p)?;
        let mut key = Vec::new();
        let mut key_len_bytes = [0; 4];
        file.read_exact(&mut key_len_bytes)?;
        let key_len = u32::from_le_bytes(key_len_bytes);
        if key_len > 4096 {
            return Err(CorruptedStorage);
        }
        key.resize(key_len as usize, 0);
        file.read_exact(&mut key)?;
        let mut name = Vec::new();
        file.read_to_end(&mut name)?;
        Ok(Some((name, key)))
    }

    pub fn set_file(&self, f: SignedFile) -> Result<(), Error> {
        let filename = encode(f.hash);
        let p = self.root.join("files").join(filename);
        if p.exists() {
            return Err(HashCollision);
        }
        let mut file = File::create(p)?;
        file.write_all(&f.user_hash)?;
        file.write_all(&f.prev_hash)?;
        file.write_all(&f.signature)?;
        self.set_prev(f.hash)?;
        Ok(())
    }

    pub fn get_file(&self, hash: [u8; 32]) -> Result<Option<SignedFile>, Error> {
        let filename = encode(hash);
        let p = self.root.join("files").join(filename);
        if !p.exists() {
            return Ok(None);
        }
        let mut file = File::open(p)?;
        let mut user_hash = [0; 32];
        file.read_exact(&mut user_hash)?;
        let mut prev_hash = [0; 32];
        file.read_exact(&mut prev_hash)?;
        let mut signature = Vec::new();
        file.read_to_end(&mut signature)?;
        Ok(Some(SignedFile {
            hash,
            user_hash,
            prev_hash,
            signature,
        }))
    }

    pub fn set_prev(&self, hash: [u8; 32]) -> Result<(), Error> {
        let p = self.root.join("prev_file");
        let mut file = File::create(p)?;
        file.write_all(&hash)?;
        Ok(())
    }

    pub fn get_prev(&self) -> Result<Option<([u8; 32], SignedFile)>, Error> {
        let p = self.root.join("prev_file");
        if !p.exists() {
            return Ok(None);
        }
        let mut file = File::open(p)?;
        let mut r = [0; 32];
        file.read_exact(&mut r)?;

        let f = self.get_file(r)?;
        return match f {
            None => Ok(None),
            Some(f) => Ok(Some((r, f))),
        };
    }
}

pub struct SignedFile {
    pub hash: [u8; 32],
    pub user_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub signature: Vec<u8>,
}
