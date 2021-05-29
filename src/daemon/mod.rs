pub use crate::ipc::ListenerError;

use crate::{
    compiler::compile,
    filter::{storage::FilterID, Loader},
    ipc::{self, Listener, Request, Response, ServerConnection},
    lang::{Filter, RuleTest},
    verifier,
};

use std::{path::PathBuf, sync::{Arc, Mutex}};

pub struct Daemon {
    listener: Listener,
    loader: Arc<Mutex<Loader>>,
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

        let loader = Arc::new(Mutex::new(Loader::new()));

        Ok(Daemon { listener, loader })
    }

    pub fn listen(&mut self) {
        while let Some(connection) = self.listener.next() {
            let loader = self.loader.clone();
            std::thread::spawn(|| handler(connection, loader));
        }
    }
}

fn handler(mut connection: ServerConnection, loader: Arc<Mutex<Loader>>) {
    while let Some(req) = connection.next() {
        let response = match req {
            Request::Compile(filter) => handler_compile(filter),
            Request::Load(id) => handler_load(id, loader.clone()),
            Request::Unload => handler_unload(loader.clone()),
            Request::Verify(filter, test) => handler_verify(filter, test),
            Request::Info => handler_info(loader.clone()),
        };

        connection.send(&response).unwrap();
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

fn handler_load(id: FilterID, loader: Arc<Mutex<Loader>>) -> Response {
    let mut loader = loader.lock().unwrap();
    let result = loader.load(id);
    Response::LoadResult(result)
}

fn handler_unload(loader: Arc<Mutex<Loader>>) -> Response {
    let mut loader = loader.lock().unwrap();
    let result = loader.unload();
    Response::LoadResult(result)
}

fn handler_verify(filter: Filter, test: RuleTest) -> Response {
    let rules = verifier::verify(&filter, &test);
    Response::VerifyResult(rules)
}

fn handler_info(loader: Arc<Mutex<Loader>>) -> Response {
    let mut loader = loader.lock().unwrap();
    let result = loader.info();
    Response::InfoResult(result)
}
