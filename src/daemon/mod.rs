pub use crate::ipc::ListenerError;

use crate::{
    compiler::compile,
    ipc::{self, Request, Response, ServerConnection, Listener},
    lang::Filter,
};

use std::path::PathBuf;

pub struct Daemon {
    listener: Listener,
}

pub enum DaemonError {
    OpenListener(ListenerError),
}

impl Daemon {
    pub fn new() -> Result<Self, DaemonError> {
        let socket_path = PathBuf::from(ipc::SOCKET_PATH);
        let pid_path = PathBuf::from(ipc::PID_PATH);
        let listener = match Listener::new(&socket_path, &pid_path) {
            Ok(listener) => listener,
            Err(err) => return Err(DaemonError::OpenListener(err)),
        };

        Ok(Daemon { listener })
    }

    pub fn listen(&mut self) {
        while let Some(connection) = self.listener.next() {
            std::thread::spawn(|| handler(connection));
        }
    }
}

fn handler(mut connection: ServerConnection) {
    while let Some(req) = connection.next() {
        match req {
            Request::Compile(filter) => {
                let result = handler_compile(filter);
                connection.send(&result).unwrap();
            },
            _ => (),
        }
    }
}

fn handler_compile(filter: Filter) -> Response {
    let obj = match compile(&filter) {
        Ok(obj) => obj,
        Err(error) => {
            return Response::CompileResult(Err(error));
        },
    };

    Response::CompileResult(Ok(obj))
}
