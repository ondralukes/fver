use crate::error::Error;
use crate::error::Error::NoDataDirectory;
use crate::remotestorage::{RemoteStorage, Signature, User};
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
use std::io::{stdin, stdout, BufRead, Read, Write};
use std::path::Path;
use std::process::exit;

mod error;
mod remotestorage;

struct Session {
    storage: RemoteStorage,
    key: PKey<Private>,
    username: String,
}

impl Session {
    fn login() -> Result<Self, Error> {
        let mut storage = RemoteStorage::new("localhost:37687")?;
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
            loop {
                print!("Enter new username: ");
                stdout().flush()?;
                let mut input = String::new();
                stdin().lock().read_line(&mut input)?;
                input.retain(|c| c != '\n' && c != '\r');
                match storage.get_user_by_username(&input)? {
                    None => {
                        username = input;
                        break;
                    }
                    Some(_) => {
                        println!("Username already registered.");
                    }
                }
            }
            key = PKey::from_ec_key(EcKey::generate(
                EcGroup::from_curve_name(Nid::SECP384R1)?.as_ref(),
            )?)?;
            create_dir_all(&config_path)?;

            let mut key_file = File::create(config_path.join("key"))?;
            key_file.write_all(&key.private_key_to_der()?)?;

            let mut username_file = File::create(config_path.join("username"))?;
            username_file.write_all(username.as_bytes())?;
        }
        match storage.get_user_by_username(&username)? {
            None => {
                println!("Key not registered. Registering.");
                let u = User {
                    key: key.public_key_to_der()?,
                    username: username.as_bytes().to_vec(),
                };
                storage.set_user(u)?;
            }
            Some(u) => {
                if u.key != key.public_key_to_der()? {
                    eprintln!("Username already registered with different key.");
                    exit(1);
                }
            }
        }
        println!("Logged in as {}", username);
        Ok(Self {
            key,
            username,
            storage: RemoteStorage::new("localhost:37687")?,
        })
    }

    fn sign<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        let mut file = File::open(path)?;
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        io::copy(&mut file, &mut hasher)?;
        let hash = hasher.finish()?.to_vec();

        let prev_sig = self.storage.get_prev()?;

        let mut signer = Signer::new_without_digest(&self.key)?;
        signer.write_all(&hash)?;
        signer.write_all(&prev_sig)?;

        let sig = Signature {
            obj: hash[..].try_into()?,
            user: self.username_hash()?,
            prev_sig,
            signature: signer.sign_to_vec()?,
        };

        println!("object hash {}", encode(&sig.obj[..8]));
        println!("user hash {}", encode(&sig.user[..8]));
        println!("previous in chain {}", encode(&sig.prev_sig[..8]));

        self.storage.add_sig(sig)?;
        println!("Signature was successfully pushed to the server.");
        Ok(())
    }

    fn verify<P: AsRef<Path>>(path: P) -> Result<(), Error> {
        let mut file = File::open(path)?;
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        io::copy(&mut file, &mut hasher)?;
        let hash = hasher.finish()?[..].try_into()?;
        println!("{}", encode(&hash));
        let mut storage = RemoteStorage::new("localhost:37687")?;
        let sigs = storage.get_obj(hash)?;
        println!(
            "Found {} signature(s) of object {}.",
            sigs.len(),
            encode(&hash[..8])
        );
        for sig in sigs {
            Session::verify_sig(&mut storage, sig)?;
        }
        Ok(())
    }

    fn verify_sig(storage: &mut RemoteStorage, hash: [u8; 32]) -> Result<(), Error> {
        let sig = storage.get_sig(hash)?;
        match sig {
            None => {
                println!("<unknown signature>");
            }
            Some(sig) => {
                let user = storage.get_user(sig.user)?;
                match user {
                    None => println!("<unknown user>"),
                    Some(u) => {
                        println!(
                            "{} (key {})",
                            String::from_utf8_lossy(&u.username),
                            encode(&u.key[..8])
                        );
                        println!("  signature hash {}", encode(&hash[..8]));
                        println!("  object hash {}", encode(&sig.obj[..8]));
                        println!("  user hash {}", encode(&sig.user[..8]));
                        println!("  previous in chain {}", encode(&sig.prev_sig[..8]));
                        let key = PKey::public_key_from_der(&u.key)?;
                        let mut verifier = Verifier::new_without_digest(key.as_ref())?;
                        verifier.write_all(&sig.obj)?;
                        verifier.write_all(&sig.prev_sig)?;
                        if verifier.verify(&sig.signature)? {
                            println!("  signature valid.");
                        } else {
                            println!("  signature INVALID.");
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

fn main() {
    let mut args = args();
    let command = args.nth(1).unwrap();
    match command.as_str() {
        "login" => {
            Session::login().unwrap();
        }
        "sign" => {
            let file = args.next().unwrap();
            let mut session = Session::login().unwrap();
            let r = session.sign(file);
            r.unwrap();
        }
        "verify" => {
            let file = args.next().unwrap();
            Session::verify(file).unwrap();
        }
        _ => {
            eprintln!("Unknown command!");
            exit(1);
        }
    }
}
