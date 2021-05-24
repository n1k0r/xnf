use nix::unistd::Pid;
use serde::{de::DeserializeOwned, Serialize};

use std::{
    io::{prelude::*, Error as IOError},
    marker::PhantomData,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
};

pub struct Listener<Send, Recv> {
    listener: UnixListener,
    sock_path: PathBuf,
    pid_path: PathBuf,
    send: PhantomData<Send>,
    recv: PhantomData<Recv>,
}

pub enum ListenerError {
    CreateSockError(PathBuf, IOError),
    RemoveSockError(PathBuf, IOError),
    ReadPIDError(PathBuf, IOError),
    WritePIDError(PathBuf, IOError),
    ChannelBusy,
}

impl<Send, Recv> Listener<Send, Recv> {
    pub fn new(sock_path: &Path, pid_path: &Path) -> Result<Self, ListenerError> {
        if pid_path.is_file() {
            let pid_str = match std::fs::read_to_string(pid_path) {
                Ok(s) => s,
                Err(err) => return Err(ListenerError::ReadPIDError(pid_path.to_path_buf(), err)),
            };

            if let Ok(pid) = pid_str.parse::<i32>() {
                let npid = Pid::from_raw(pid);
                if let Ok(()) = nix::sys::signal::kill(npid, None) {
                    return Err(ListenerError::ChannelBusy);
                }
            }
        }

        let pid = std::process::id();
        let pid_str = format!("{}", pid);
        if let Err(err) = std::fs::write(pid_path, pid_str) {
            return Err(ListenerError::WritePIDError(pid_path.to_path_buf(), err));
        }

        if sock_path.exists() {
            if let Err(err) = std::fs::remove_file(sock_path) {
                return Err(ListenerError::RemoveSockError(sock_path.to_path_buf(), err));
            }
        }

        let listener = match UnixListener::bind(sock_path) {
            Ok(listener) => listener,
            Err(err) => return Err(ListenerError::CreateSockError(sock_path.to_path_buf(), err)),
        };

        Ok(Self {
            listener,
            sock_path: sock_path.to_path_buf(),
            pid_path: pid_path.to_path_buf(),
            send: PhantomData,
            recv: PhantomData,
        })
    }
}

impl<Send, Recv> Drop for Listener<Send, Recv> {
    fn drop(&mut self) {
        std::fs::remove_file(&self.sock_path).unwrap();
        std::fs::remove_file(&self.pid_path).unwrap();
    }
}

impl<Send, Recv> Iterator for Listener<Send, Recv> {
    type Item = Connection<Send, Recv>;

    fn next(&mut self) -> Option<Self::Item> {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(_) => return None,
        };

        let connection = Connection::from(stream);
        Some(connection)
    }
}

pub struct Connection<Send, Recv> {
    stream: UnixStream,
    send: PhantomData<Send>,
    recv: PhantomData<Recv>,
}

impl<Send, Recv> Connection<Send, Recv>
where Send: Serialize {
    pub fn new(path: &Path) -> Result<Self, IOError> {
        let stream = UnixStream::connect(path)?;

        let connection = Self::from(stream);
        Ok(connection)
    }

    pub fn send(&mut self, msg: &Send) -> Result<(), IOError> {
        let bytes = bincode::serialize(&msg).unwrap();

        let len = bytes.len() as u32;
        let bsize = len.to_ne_bytes();

        self.stream.write_all(&bsize)?;
        self.stream.write_all(&bytes)?;

        Ok(())
    }
}

impl<Send, Recv> From<UnixStream> for Connection<Send, Recv> {
    fn from(stream: UnixStream) -> Self {
        Self {
            stream,
            send: PhantomData,
            recv: PhantomData,
        }
    }
}

impl<Req, Resp> Iterator for Connection<Req, Resp>
where Resp: DeserializeOwned {
    type Item = Resp;

    fn next(&mut self) -> Option<Self::Item> {
        let mut bsize = [0; 4];
        if let Err(_) = self.stream.read_exact(&mut bsize) {
            return None;
        }
        let size = u32::from_ne_bytes(bsize) as usize;

        let mut bytes = vec![0; size];
        if let Err(_) = self.stream.read_exact(&mut bytes) {
            return None;
        }

        let resp: Resp = match bincode::deserialize(&bytes) {
            Ok(resp) => resp,
            Err(_) => return None,
        };
        Some(resp)
    }
}
