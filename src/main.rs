mod error;
mod localstorage;

extern crate dirs;
extern crate hex;
extern crate openssl;

use crate::error::Error;
use crate::error::Error::NoDataDirectory;
use crate::localstorage::LocalStorage;
use dirs::data_dir;
use hex::encode;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
use openssl::sign::{Signer, Verifier};
use std::convert::TryInto;
use std::env::args;
use std::fs::{create_dir_all, File};
use std::io;
use std::io::{stdin, stdout, BufRead, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::exit;

struct Session {
    key: PKey<Private>,
    username: String,
}

impl Session {
    fn login() -> Result<Self, Error> {
        let mut config_path = data_dir().ok_or(NoDataDirectory)?;
        config_path.push("fver");
        let key;
        let username;
        if config_path.exists() {
            let mut keyfile = File::open(config_path.join("key"))?;
            let mut der = Vec::new();
            keyfile.read_to_end(&mut der)?;
            key = PKey::from_ec_key(EcKey::private_key_from_der(&der)?)?;
            let mut username_file = File::open(config_path.join("username"))?;
            let mut username_vec = Vec::new();
            username_file.read_to_end(&mut username_vec)?;
            username = String::from_utf8(username_vec)?;
        } else {
            print!("Enter new username: ");
            stdout().flush()?;
            let mut input = String::new();
            stdin().lock().read_line(&mut input)?;
            input.retain(|c| c != '\n' && c != '\r');
            username = input;
            key = PKey::from_ec_key(EcKey::generate(
                EcGroup::from_curve_name(Nid::SECP384R1)?.as_ref(),
            )?)?;
            create_dir_all(&config_path)?;

            let mut key_file = File::create(config_path.join("key"))?;
            key_file.write_all(&key.private_key_to_der()?)?;

            let mut username_file = File::create(config_path.join("username"))?;
            username_file.write_all(username.as_bytes())?;
        }
        let storage = LocalStorage::new("lks")?;
        match storage.get_key_by_username(&username)? {
            None => {
                println!("Key not registered. Registering.");
                storage.set_key(&key.public_key_to_der()?, &username)?;
            }
            _ => {}
        }
        println!("Logged in as {}", username);
        Ok(Self { key, username })
    }

    fn sign<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let mut file = File::open(path)?;
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        let mut signer = Signer::new_without_digest(&self.key)?;
        hash_and_sign(&mut file, &mut hasher, &mut signer)?;
        let hash = hasher.finish()?;
        let signature = signer.sign_to_vec()?;
        println!("{}", encode(&hash));
        LocalStorage::new("lks").unwrap().set_file(
            hash.as_ref().try_into().unwrap(),
            self.username_hash()?,
            &signature,
        )?;
        Ok(())
    }

    fn verify<P: AsRef<Path>>(path: P) -> Result<(), Error> {
        let mut file = File::open(path)?;
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        io::copy(&mut file, &mut hasher)?;
        let hash = hasher.finish()?;
        println!("{}", encode(&hash));
        let storage = LocalStorage::new("lks")?;
        let file_sig = storage.get_file(hash.as_ref().try_into().unwrap())?;
        match file_sig {
            None => {
                println!("No signature found.");
                exit(1);
            }
            Some((user_hash, signature)) => {
                let user = storage.get_key(user_hash)?;
                match user {
                    None => {
                        println!("Key not found.");
                        exit(1);
                    }
                    Some((username, key)) => {
                        let key = PKey::public_key_from_der(&key)?;
                        let mut verifier = Verifier::new_without_digest(key.as_ref())?;
                        file.seek(SeekFrom::Start(0))?;
                        io::copy(&mut file, &mut verifier)?;
                        if verifier.verify(&signature)? {
                            println!("Signed by {}", username);
                        } else {
                            println!("INVALID signature");
                            exit(1);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn username_hash(&self) -> Result<[u8; 32], Error> {
        Ok(sha256(self.username.as_bytes()))
    }
}

fn hash_and_sign<R: Read>(
    reader: &mut R,
    hasher: &mut Hasher,
    signer: &mut Signer,
) -> io::Result<()> {
    let mut buf = Vec::new();
    buf.resize(1024, 0);
    loop {
        match reader.read(&mut buf) {
            Ok(read) => {
                if read == 0 {
                    hasher.flush()?;
                    signer.flush()?;
                    return Ok(());
                }
                hasher.write_all(&buf[..read])?;
                signer.write_all(&buf[..read])?;
            }
            Err(err) if err.kind() != ErrorKind::Interrupted => return Err(err),
            _ => {}
        }
    }
}

fn main() {
    let mut args = args();
    let command = args.nth(1).unwrap();
    match command.as_str() {
        "login" => {
            Session::login().unwrap();
        }
        "sign" => {
            let file = args.next().unwrap();
            let session = Session::login().unwrap();
            session.sign(file).unwrap();
        }
        "verify" => {
            let file = args.next().unwrap();
            Session::verify(file).unwrap();
        }
        "key" => {
            let username = args.next().unwrap();
            let key = LocalStorage::new("lks")
                .unwrap()
                .get_key_by_username(&username)
                .unwrap();
            match key {
                None => {
                    println!("No such key.");
                }
                Some((username, key)) => {
                    println!("Key for {} : {}", username, encode(key));
                }
            }
        }
        _ => {
            eprintln!("Unknown command!");
            exit(1);
        }
    }
}
