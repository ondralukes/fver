use std::convert::TryInto;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{spawn, JoinHandle};

use simpletcp::simpletcp::{Message, TcpStream};
use simpletcp::utils::{get_fd_array, poll_set_timeout, EV_POLLIN};

use crate::error::Error;
use crate::error::Error::{CorruptedMessage, UnknownCommand};
use crate::localstorage::LocalStorage;
use crate::threadpool::ThreadMessage::{Accept, Stop};

pub struct Server {
    threads: Vec<Thread>,
    next_accept: usize,
}

impl Server {
    pub fn new<P: AsRef<Path>>(n: usize, path: P) -> Self {
        let mut threads = Vec::new();
        let storage = Arc::new(Mutex::new(LocalStorage::new(path).unwrap()));
        threads.resize_with(n, || Thread::new(storage.clone()));
        Self {
            threads,
            next_accept: 0,
        }
    }

    pub fn accept(&mut self, client: TcpStream) {
        self.threads[self.next_accept]
            .tx
            .send(Accept(client))
            .unwrap();
        self.next_accept += 1;
        if self.next_accept == self.threads.len() {
            self.next_accept = 0;
        }
    }
}

enum ThreadMessage {
    Stop,
    Accept(TcpStream),
}

struct Thread {
    join_handle: JoinHandle<()>,
    tx: Sender<ThreadMessage>,
}

impl Thread {
    fn new(storage: Arc<Mutex<LocalStorage>>) -> Self {
        let (tx, rx) = channel();
        let join_handle = spawn(|| {
            thread_loop(rx, storage);
        });
        Self { tx, join_handle }
    }
}

fn thread_loop(rx: Receiver<ThreadMessage>, storage: Arc<Mutex<LocalStorage>>) {
    let mut clients = Vec::new();
    let mut fds = Vec::new();
    loop {
        match rx.try_recv() {
            Ok(m) => match m {
                Stop => {
                    break;
                }
                Accept(client) => {
                    clients.push(client);
                    fds = get_fd_array(&clients);
                }
            },
            Err(_) => {}
        }
        match poll_set_timeout(&mut fds, EV_POLLIN, 50) {
            None => {}
            Some(n) => {
                let mut remove = false;
                let client = &mut clients[n as usize];
                match client.read() {
                    Ok(m) => match m {
                        None => {}
                        Some(m) => match process_message(m, &storage) {
                            Ok(resp) => match client.write(&resp) {
                                Ok(_) => {}
                                Err(_) => {
                                    remove = true;
                                }
                            },
                            Err(_) => {
                                remove = true;
                            }
                        },
                    },
                    Err(e) => match e {
                        simpletcp::simpletcp::Error::NotReady => match client.get_ready() {
                            Ok(_) => {}
                            Err(_) => {
                                remove = true;
                            }
                        },
                        _ => {
                            remove = true;
                        }
                    },
                }
                if remove {
                    clients.remove(n as usize);
                    fds = get_fd_array(&clients);
                }
            }
        }
    }
}

fn process_message(mut m: Message, storage: &Mutex<LocalStorage>) -> Result<Message, Error> {
    return match m.read_u8()? {
        // set_key
        0 => {
            let storage = storage.lock().unwrap();
            let key = m.read_buffer()?.to_vec();
            let username = m.read_buffer()?.to_vec();

            let mut resp = Message::new();
            match storage.set_key(&key, &username) {
                Ok(_) => {
                    resp.write_i8(0);
                }
                Err(_) => {
                    resp.write_i8(-1);
                }
            }
            Ok(resp)
        }

        // get_key
        1 => {
            let storage = storage.lock().unwrap();
            let user_hash = m.read_buffer()?;
            let mut resp = Message::new();
            let r = storage.get_key(
                user_hash
                    .try_into()
                    .or_else(|_| Err(CorruptedMessage))
                    .unwrap(),
            );
            match r {
                Ok(opt) => match opt {
                    None => {
                        resp.write_i8(0);
                        Ok(resp)
                    }
                    Some((username, key)) => {
                        resp.write_i8(1);
                        resp.write_buffer(&username);
                        resp.write_buffer(&key);
                        Ok(resp)
                    }
                },
                Err(_) => {
                    resp.write_i8(-1);
                    Ok(resp)
                }
            }
        }

        //get_file
        2 => {
            let hash = m.read_buffer()?;
            let storage = storage.lock().unwrap();
            let mut resp = Message::new();
            return match storage.get_file(hash.try_into()?) {
                Ok(opt) => match opt {
                    None => {
                        resp.write_i8(0);
                        Ok(resp)
                    }
                    Some((user_hash, signature)) => {
                        resp.write_i8(1);
                        resp.write_buffer(&user_hash);
                        resp.write_buffer(&signature);
                        Ok(resp)
                    }
                },
                Err(_) => {
                    resp.write_i8(-1);
                    Ok(resp)
                }
            };
        }

        //set_file
        3 => {
            let hash = m.read_buffer()?.to_vec();
            let user_hash = m.read_buffer()?.to_vec();
            let signature = m.read_buffer()?.to_vec();
            if hash.len() < 32 || hash.len() < 32 {
                return Err(CorruptedMessage);
            }

            let storage = storage.lock().unwrap();
            let mut resp = Message::new();
            return match storage.set_file(
                (&hash[..32]).try_into()?,
                (&user_hash[..32]).try_into()?,
                &signature,
            ) {
                Ok(_) => {
                    resp.write_i8(0);
                    Ok(resp)
                }
                Err(_) => {
                    resp.write_i8(-1);
                    Ok(resp)
                }
            };
        }
        _ => Err(UnknownCommand),
    };
}
