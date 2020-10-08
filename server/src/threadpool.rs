use std::convert::TryInto;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn};

use simpletcp::simpletcp::{Message, TcpStream};
use simpletcp::utils::{get_fd_array, poll_set_timeout, EV_POLLIN};

use crate::error::Error;
use crate::error::Error::{CorruptedMessage, CorruptedStorage};
use crate::localstorage::{LocalStorage, SignedFile};
use crate::threadpool::ClientAction::{Disconnect, Enqueue, Respond};
use crate::threadpool::ThreadMessage::Accept;
use std::time::Duration;

pub struct Server {
    threads: Vec<Thread>,
    next_accept: usize,
}

impl Server {
    pub fn new<P: AsRef<Path>>(n: usize, path: P) -> Self {
        let (queue_tx, queue_rx) = channel();
        let mut threads = Vec::new();
        let storage = Arc::new(Mutex::new(LocalStorage::new(path).unwrap()));
        let storage_clone = storage.clone();
        spawn(|| {
            queue_loop(queue_rx, storage_clone);
        });
        threads.resize_with(n, || Thread::new(storage.clone(), queue_tx.clone()));
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
    Accept(TcpStream),
}

enum ClientAction {
    Respond(Message),
    Enqueue,
    Disconnect,
    None,
}

macro_rules! c_try {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(_) => {
                return Disconnect;
            }
        }
    };
}

struct Thread {
    tx: Sender<ThreadMessage>,
}

impl Thread {
    fn new(storage: Arc<Mutex<LocalStorage>>, queue_tx: Sender<ThreadMessage>) -> Self {
        let (tx, rx) = channel();
        spawn(|| {
            thread_loop(rx, storage, queue_tx);
        });
        Self { tx }
    }
}

fn thread_loop(
    rx: Receiver<ThreadMessage>,
    storage: Arc<Mutex<LocalStorage>>,
    queue_tx: Sender<ThreadMessage>,
) {
    let mut clients = Vec::new();
    let mut fds = Vec::new();
    loop {
        match rx.try_recv() {
            Ok(m) => match m {
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
                let mut action = ClientAction::None;
                let client = &mut clients[n as usize];
                match client.read() {
                    Ok(m) => match m {
                        None => {}
                        Some(m) => {
                            action = process_message(m, &storage);
                        }
                    },
                    Err(e) => match e {
                        simpletcp::simpletcp::Error::NotReady => match client.get_ready() {
                            Ok(_) => {}
                            Err(_) => {
                                action = Disconnect;
                            }
                        },
                        _ => {
                            action = Disconnect;
                        }
                    },
                }
                match action {
                    Respond(m) => match client.write(&m) {
                        Ok(_) => {}
                        Err(_) => {
                            clients.remove(n as usize);
                            fds = get_fd_array(&clients);
                        }
                    },
                    Enqueue => {
                        let client = clients.remove(n as usize);
                        fds = get_fd_array(&clients);
                        queue_tx.send(Accept(client));
                    }
                    Disconnect => {
                        clients.remove(n as usize);
                        fds = get_fd_array(&clients);
                    }
                    ClientAction::None => {}
                }
            }
        }
    }
}

fn process_message(mut m: Message, storage: &Mutex<LocalStorage>) -> ClientAction {
    return match c_try!(m.read_u8()) {
        // set_key
        0 => {
            let storage = storage.lock().unwrap();
            let key = c_try!(m.read_buffer()).to_vec();
            let username = c_try!(m.read_buffer()).to_vec();

            let mut resp = Message::new();
            match storage.set_key(&key, &username) {
                Ok(_) => {
                    resp.write_i8(0);
                }
                Err(_) => {
                    resp.write_i8(-1);
                }
            }
            Respond(resp)
        }

        // get_key
        1 => {
            let storage = storage.lock().unwrap();
            let user_hash = c_try!(m.read_buffer());
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
                        Respond(resp)
                    }
                    Some((username, key)) => {
                        resp.write_i8(1);
                        resp.write_buffer(&username);
                        resp.write_buffer(&key);
                        Respond(resp)
                    }
                },
                Err(_) => {
                    resp.write_i8(-1);
                    Respond(resp)
                }
            }
        }

        //get_file
        2 => {
            let hash = c_try!(m.read_buffer());
            let storage = storage.lock().unwrap();
            let mut resp = Message::new();
            return match storage.get_file(c_try!(hash.try_into())) {
                Ok(opt) => match opt {
                    None => {
                        resp.write_i8(0);
                        Respond(resp)
                    }
                    Some(f) => {
                        resp.write_i8(1);
                        resp.write_buffer(&f.hash);
                        resp.write_buffer(&f.user_hash);
                        resp.write_buffer(&f.prev_hash);
                        resp.write_buffer(&f.signature);
                        Respond(resp)
                    }
                },
                Err(_) => {
                    resp.write_i8(-1);
                    Respond(resp)
                }
            };
        }

        // request_enqueue
        4 => Enqueue,
        _ => Disconnect,
    };
}

fn queue_loop(rx: Receiver<ThreadMessage>, storage: Arc<Mutex<LocalStorage>>) {
    loop {
        match rx.try_recv() {
            Ok(m) => match m {
                Accept(client) => {
                    handle_enqueue(client, &storage);
                }
            },
            Err(_) => {}
        }
    }
}

fn handle_enqueue(mut client: TcpStream, storage: &Arc<Mutex<LocalStorage>>) -> Result<(), Error> {
    let storage = storage.lock().unwrap();
    let mut prev_hash = [0; 32];
    match storage.get_prev() {
        Ok(prev) => match prev {
            Some((hash, f)) => {
                prev_hash = hash;
                let mut m = Message::new();
                m.write_i8(1);
                m.write_buffer(&f.hash);
                m.write_buffer(&f.user_hash);
                m.write_buffer(&f.prev_hash);
                m.write_buffer(&f.signature);
                client.write(&m)?;
            }
            None => {
                let mut m = Message::new();
                m.write_i8(0);
                client.write(&m)?;
            }
        },
        Err(_) => {
            let mut m = Message::new();
            m.write_i8(-1);
            client.write(&m)?;
            return Err(CorruptedStorage);
        }
    }

    match client.read_timeout(1000) {
        Ok(m) => match m {
            None => {}
            Some(mut m) => {
                let hash = m.read_buffer()?.to_vec();
                let user_hash = m.read_buffer()?.to_vec();
                let signature = m.read_buffer()?.to_vec();
                if hash.len() < 32 || hash.len() < 32 {
                    return Err(CorruptedMessage);
                }

                let mut resp = Message::new();
                match storage.set_file(SignedFile {
                    hash: (&hash[..32]).try_into()?,
                    user_hash: (&user_hash[..32]).try_into()?,
                    prev_hash,
                    signature,
                }) {
                    Ok(_) => {
                        resp.write_i8(0);
                    }
                    Err(_) => {
                        resp.write_i8(-1);
                    }
                };
                client.write(&resp)?;
            }
        },
        Err(_) => {
            println!("e");
        }
    }
    Ok(())
}
