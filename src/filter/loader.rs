use super::storage::{FilterID, FilterStorage};

use bpf::{Link, Object};
use libbpf_rs as bpf;
use nix::{self, sys::socket::SockAddr};
use serde::{Deserialize, Serialize};

use std::{collections::HashMap, path::Path, sync::mpsc::{self, Sender, Receiver}};

#[allow(dead_code)]
struct LoadedFilter {
    object: Object,
    link: Link,
}

enum LoadRequest {
    Load(FilterID),
    Unload,
}

type LoadResponse = Result<(), LoadError>;

pub struct Loader {
    sender: Sender<LoadRequest>,
    receiver: Receiver<LoadResponse>,
}

struct LoaderThread {
    sender: Sender<LoadResponse>,
    receiver: Receiver<LoadRequest>,
    filters: HashMap<String, LoadedFilter>,
    debug: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LoadError {
    StorageNotExist(FilterID),
    InvalidStorage(FilterID),
    MarkStorage(FilterID, String),
    UnmarkStorage(String),
    IfacesList,
    IfaceNotExist(String),
    Open(String),
    Load(String),
    Attach(String),
    InternalError,
}

impl Loader {
    pub fn new() -> Self {
        let (req_tx, req_rx) = mpsc::channel();
        let (resp_tx, resp_rx) = mpsc::channel();

        std::thread::spawn(|| {
            let mut loader = LoaderThread::new(req_rx, resp_tx);
            loader.work();
        });

        Loader {
            sender: req_tx,
            receiver: resp_rx,
        }
    }

    pub fn load(&mut self, id: FilterID) -> Result<(), LoadError> {
        if let Err(_) = self.sender.send(
            LoadRequest::Load(id.clone())
        ) {
            return Err(LoadError::InternalError);
        }

        let resp = match self.receiver.recv() {
            Ok(resp) => resp,
            Err(_) => return Err(LoadError::InternalError),
        };

        resp
    }

    pub fn unload(&mut self) -> Result<(), LoadError> {
        if let Err(_) = self.sender.send(LoadRequest::Unload) {
            return Err(LoadError::InternalError);
        }

        let resp = match self.receiver.recv() {
            Ok(resp) => resp,
            Err(_) => return Err(LoadError::InternalError),
        };

        resp
    }
}

impl LoaderThread {
    pub fn new(rx: Receiver<LoadRequest>, tx: Sender<LoadResponse>) -> Self {
        let mut loader = Self {
            receiver: rx,
            sender: tx,
            filters: HashMap::new(),
            debug: false,
        };

        if let Some(storage) = FilterStorage::load_current() {
            let _ = loader.load(&storage);
        }

        loader
    }

    pub fn work(&mut self) {
        while let Ok(req) = self.receiver.recv() {
            let result = match req {
                LoadRequest::Load(id) => self.request_load(id),
                LoadRequest::Unload => self.request_unload(),
            };
            self.sender.send(result).unwrap();
        }
    }

    fn request_load(&mut self, id: FilterID) -> LoadResponse {
        let storage = match FilterStorage::load(id) {
            Some(storage) => storage,
            None => return Err(LoadError::StorageNotExist(id)),
        };

        if let Err(err) = self.load(&storage) {
            return Err(err);
        }

        Ok(())
    }

    fn request_unload(&mut self) -> LoadResponse {
        if let Err(err) = self.unload() {
            return Err(err);
        }

        Ok(())
    }

    fn unload(&mut self) -> Result<(), LoadError> {
        if let Err(err) = FilterStorage::remove_mark() {
            return Err(LoadError::UnmarkStorage(err.to_string()));
        }
        self.filters.clear();

        Ok(())
    }

    fn load(&mut self, storage: &FilterStorage) -> Result<(), LoadError> {
        if let Err(err) = storage.mark_current() {
            return Err(LoadError::MarkStorage(storage.id(), err.to_string()));
        }

        let default = match storage.get_object(None) {
            Some(path) => path,
            None => return Err(LoadError::InvalidStorage(storage.id())),
        };

        let ifaces = match get_ifaces() {
            Some(ifaces) => ifaces,
            None => return Err(LoadError::IfacesList),
        };

        for iface in ifaces.iter() {
            let path = storage.get_object(Some(iface));
            let path = path.as_ref().unwrap_or(&default);
            self.load_iface(&path, iface)?;
        }

        Ok(())
    }

    fn load_iface(&mut self, path: &Path, iface: &str) -> Result<(), LoadError> {
        let ifindex = match get_ifindex(iface) {
            Some(index) => index,
            None => return Err(LoadError::IfaceNotExist(iface.to_string())),
        };

        let mut builder = bpf::ObjectBuilder::default();
        builder.debug(self.debug);

        let mut openobj = match builder.open_file(path) {
            Ok(openobj) => openobj,
            Err(error) => return Err(
                LoadError::Open(format!("{}", error))
            ),
        };
        let oprog = openobj.prog("main").unwrap().unwrap();
        oprog.set_prog_type(bpf::ProgramType::Xdp);

        let mut obj = match openobj.load() {
            Ok(obj) => obj,
            Err(error) => return Err(
                LoadError::Load(format!("{}", error))
            ),
        };

        let prog = obj.prog_unwrap("main");

        self.filters.remove(iface);

        let link = match prog.attach_xdp(ifindex as i32) {
            Ok(link) => link,
            Err(error) => return Err(
                LoadError::Attach(format!("{}", error))
            ),
        };

        self.filters.insert(iface.to_string(), LoadedFilter {
            object: obj,
            link: link,
        });

        Ok(())
    }
}

fn get_ifaces() -> Option<Vec<String>> {
    let mut ifaces = vec![];

    let iface_it = match nix::ifaddrs::getifaddrs() {
        Ok(it) => it,
        Err(_) => return None,
    };

    for iface in iface_it {
        if let Some(SockAddr::Link(_)) = iface.address {
            ifaces.push(iface.interface_name);
        }
    }

    Some(ifaces)
}

fn get_ifindex(iface_name: &str) -> Option<usize> {
    let iface_it = match nix::ifaddrs::getifaddrs() {
        Ok(it) => it,
        Err(_) => return None,
    };

    for iface in iface_it {
        if iface.interface_name == iface_name {
            if let Some(SockAddr::Link(addr)) = iface.address {
                return Some(addr.ifindex());
            }
        }
    }

    None
}
