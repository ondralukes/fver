use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use hex::encode;
use openssl::sha::sha256;

use crate::error::Error;
use crate::error::Error::{CorruptedMessage, CorruptedStorage, HashCollision, IOError};
use openssl::hash::{Hasher, MessageDigest};
use std::convert::TryInto;

pub struct LocalStorage {
    root: PathBuf,
}

impl LocalStorage {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let root = PathBuf::from(path.as_ref());
        create_dir_all(root.join("user"))?;
        create_dir_all(root.join("sig"))?;
        create_dir_all(root.join("obj"))?;
        create_dir_all(root.join("files"))?;
        Ok(Self { root })
    }

    pub fn set_prev(&self, hash: [u8; 32]) -> Result<(), Error> {
        let p = self.root.join("prev_sig");
        let mut file = File::create(p)?;
        file.write_all(&hash)?;
        Ok(())
    }

    pub fn get_prev(&self) -> Result<Option<[u8; 32]>, Error> {
        let p = self.root.join("prev_sig");
        if !p.exists() {
            return Ok(None);
        }
        let mut file = File::open(p)?;
        let mut r = [0; 32];
        file.read_exact(&mut r)?;

        Ok(Some(r))
    }

    pub fn set_user(&mut self, u: User) -> Result<(), Error> {
        let hash = sha256(&u.username);
        let filename = encode(hash);
        let p = self.root.join("user").join(filename);
        if p.exists() {
            return Err(HashCollision);
        }
        let mut file = File::create(p)?;
        u.write_to(&mut file)?;
        Ok(())
    }

    pub fn get_user(&mut self, hash: &[u8]) -> Result<Option<User>, Error> {
        if hash.len() != 32 {
            return Err(CorruptedMessage);
        }
        let filename = encode(hash);
        let p = self.root.join("user").join(filename);
        if !p.exists() {
            return Ok(None);
        }
        let mut file = File::open(p)?;
        Ok(Some(User::read_from(&mut file)?))
    }

    pub fn get_obj(&mut self, hash: &[u8]) -> Result<Option<Object>, Error> {
        if hash.len() != 32 {
            return Err(CorruptedMessage);
        }
        let filename = encode(hash);
        let p = self.root.join("obj").join(filename);
        if !p.exists() {
            return Ok(None);
        }
        let mut file = File::open(p)?;
        let mut sigs = Vec::new();

        let mut buf = [0; 32];
        loop {
            match file.read_exact(&mut buf) {
                Ok(_) => {
                    sigs.push(buf);
                }
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => {
                    return Err(IOError(e));
                }
            }
        }
        Ok(Some(Object { sigs }))
    }

    pub fn add_sig(&mut self, sig: Signature) -> Result<(), Error> {
        let sig_hash = sig.hash()?;
        let mut filename = encode(sig_hash);
        let mut p = self.root.join("sig").join(filename);
        if p.exists() {
            return Err(HashCollision);
        }
        let mut file = File::create(p)?;
        sig.write_to(&mut file)?;

        filename = encode(sig.obj);
        p = self.root.join("obj").join(filename);
        file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(p)?;
        file.write_all(&sig_hash)?;
        self.set_prev(sig_hash)?;
        Ok(())
    }

    pub fn get_sig(&self, hash: &[u8]) -> Result<Option<Signature>, Error> {
        if hash.len() != 32 {
            return Err(CorruptedMessage);
        }
        let filename = encode(hash);
        let p = self.root.join("sig").join(filename);
        if !p.exists() {
            return Ok(None);
        }
        let mut file = File::open(p)?;
        Ok(Some(Signature::read_from(&mut file)?))
    }
}

pub struct User {
    pub(crate) username: Vec<u8>,
    pub(crate) key: Vec<u8>,
}

impl User {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write_all(&(self.key.len() as u32).to_le_bytes())?;
        writer.write_all(&self.key)?;
        writer.write_all(&self.username)?;
        Ok(())
    }

    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut key = Vec::new();
        let mut key_len_bytes = [0; 4];
        reader.read_exact(&mut key_len_bytes)?;
        let key_len = u32::from_le_bytes(key_len_bytes);
        if key_len > 4096 {
            return Err(CorruptedStorage);
        }
        key.resize(key_len as usize, 0);
        reader.read_exact(&mut key)?;
        let mut username = Vec::new();
        reader.read_to_end(&mut username)?;
        Ok(Self { username, key })
    }
}

pub struct Object {
    pub(crate) sigs: Vec<[u8; 32]>,
}

pub struct Signature {
    pub(crate) obj: [u8; 32],
    pub(crate) user: [u8; 32],
    pub(crate) prev_sig: [u8; 32],
    pub(crate) signature: Vec<u8>,
}

impl Signature {
    fn hash(&self) -> Result<[u8; 32], Error> {
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        self.write_to(&mut hasher)?;
        let hash = hasher.finish()?;
        Ok((&hash[..32]).try_into()?)
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write_all(&self.obj)?;
        writer.write_all(&self.user)?;
        writer.write_all(&self.prev_sig)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }

    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut obj = [0; 32];
        reader.read_exact(&mut obj)?;
        let mut user = [0; 32];
        reader.read_exact(&mut user)?;
        let mut prev_sig = [0; 32];
        reader.read_exact(&mut prev_sig)?;
        let mut signature = Vec::new();
        reader.read_to_end(&mut signature)?;
        Ok(Self {
            obj,
            user,
            prev_sig,
            signature,
        })
    }
}
