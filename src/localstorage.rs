use crate::error::Error;
use crate::error::Error::{HashCollision, IllegalState};
use hex::encode;
use openssl::sha::sha256;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

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

    pub fn set_key(&self, key: &[u8], username: &str) -> Result<(), Error> {
        let hash = sha256(username.as_bytes());
        let filename = encode(hash);
        let p = self.root.join("keys").join(filename);
        if p.exists() {
            return Err(HashCollision);
        }
        let mut file = File::create(p)?;
        file.write_all(&(key.len() as u32).to_le_bytes())?;
        file.write_all(key)?;
        file.write_all(username.as_bytes())?;
        Ok(())
    }

    pub fn get_key_by_username(&self, username: &str) -> Result<Option<(String, Vec<u8>)>, Error> {
        let hash = sha256(username.as_bytes());
        self.get_key(hash)
    }

    pub fn get_key(&self, user_hash: [u8; 32]) -> Result<Option<(String, Vec<u8>)>, Error> {
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
            return Err(IllegalState);
        }
        key.resize(key_len as usize, 0);
        file.read_exact(&mut key)?;
        let mut name = Vec::new();
        file.read_to_end(&mut name)?;
        Ok(Some((String::from_utf8(name)?, key)))
    }

    pub fn set_file(
        &self,
        hash: [u8; 32],
        user_hash: [u8; 32],
        signature: &[u8],
    ) -> Result<(), Error> {
        let filename = encode(hash);
        let p = self.root.join("files").join(filename);
        if p.exists() {
            return Err(HashCollision);
        }
        let mut file = File::create(p)?;
        file.write_all(&user_hash)?;
        file.write_all(&signature)?;
        Ok(())
    }

    pub fn get_file(&self, hash: [u8; 32]) -> Result<Option<([u8; 32], Vec<u8>)>, Error> {
        let filename = encode(hash);
        let p = self.root.join("files").join(filename);
        if !p.exists() {
            return Ok(None);
        }
        let mut file = File::open(p)?;
        let mut user_hash = [0; 32];
        file.read_exact(&mut user_hash)?;
        let mut signature = Vec::new();
        file.read_to_end(&mut signature)?;
        Ok(Some((user_hash, signature)))
    }
}
