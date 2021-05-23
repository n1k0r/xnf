use serde::{de::DeserializeOwned, Serialize};

use std::os::unix::net::{UnixListener, UnixStream};
use std::{
    io::{prelude::*, Error as IOError},
    marker::PhantomData,
    path::Path,
};

pub struct Listener<Send, Recv> {
    listener: UnixListener,
    send: PhantomData<Send>,
    recv: PhantomData<Recv>,
}

impl<Send, Recv> Listener<Send, Recv> {
    pub fn new(path: &Path) -> Option<Self> {
        let listener = match UnixListener::bind(path) {
            Ok(listener) => listener,
            Err(_) => return None,
        };

        Some(Self {
            listener,
            send: PhantomData,
            recv: PhantomData,
        })
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
    pub fn new(path: &Path) -> Option<Self> {
        let stream = match UnixStream::connect(path) {
            Ok(stream) => stream,
            Err(_) => return None,
        };

        let connection = Self::from(stream);
        Some(connection)
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
