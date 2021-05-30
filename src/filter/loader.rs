use crate::compiler;
use super::{stats::Stats, storage::{FilterID, FilterStorage}};

use bpf::{Link, Object, libbpf_sys};
use libbpf_rs as bpf;
use nix::{self, sys::socket::SockAddr};
use serde::{Deserialize, Serialize};

use std::{
    collections::HashMap,
    ffi,
    mem::size_of,
    path::Path,
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
};

pub const STATS_UPDATE_INTERVAL: u64 = 1000;

pub struct Loader {
    sender: Sender<LoadRequest>,
    receiver: Receiver<LoadResponse>,
}

struct LoaderThread {
    sender: Sender<LoadResponse>,
    receiver: Receiver<LoadRequest>,
    stats: Arc<Mutex<Stats>>,
    filters: HashMap<String, LoadedFilter>,
    debug: bool,
}

#[allow(dead_code)]
struct LoadedFilter {
    id: FilterID,
    object: Object,
    link: Link,
}

enum LoadRequest {
    Load(FilterID),
    Unload,
    Info,
    StatsTimer,
}

enum LoadResponse {
    Load(Result<(), LoadError>),
    Info(Result<Vec<IfaceInfo>, LoadError>),
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

#[derive(Debug, Serialize, Deserialize)]
pub struct IfaceInfo {
    pub name: String,
    pub filter: Option<FilterID>,
}

impl Loader {
    pub fn new(stats: Arc<Mutex<Stats>>) -> Self {
        let (req_tx, req_rx) = mpsc::channel();
        let (resp_tx, resp_rx) = mpsc::channel();

        std::thread::spawn(|| {
            let mut loader = LoaderThread::new(req_rx, resp_tx, stats);
            loader.work();
        });

        let timer_tx = req_tx.clone();
        std::thread::spawn(move || {
            let duration = std::time::Duration::from_millis(STATS_UPDATE_INTERVAL);

            loop {
                std::thread::sleep(duration);
                let _ = timer_tx.send(LoadRequest::StatsTimer);
            }
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
            Ok(LoadResponse::Load(resp)) => resp,
            _ => return Err(LoadError::InternalError),
        };

        resp
    }

    pub fn unload(&mut self) -> Result<(), LoadError> {
        if let Err(_) = self.sender.send(LoadRequest::Unload) {
            return Err(LoadError::InternalError);
        }

        let resp = match self.receiver.recv() {
            Ok(LoadResponse::Load(resp)) => resp,
            _ => return Err(LoadError::InternalError),
        };

        resp
    }

    pub fn info(&mut self) -> Result<Vec<IfaceInfo>, LoadError> {
        if let Err(_) = self.sender.send(LoadRequest::Info) {
            return Err(LoadError::InternalError);
        }

        let resp = match self.receiver.recv() {
            Ok(LoadResponse::Info(resp)) => resp,
            _ => return Err(LoadError::InternalError),
        };

        resp
    }
}

impl LoaderThread {
    pub fn new(rx: Receiver<LoadRequest>, tx: Sender<LoadResponse>, stats: Arc<Mutex<Stats>>) -> Self {
        let mut loader = Self {
            receiver: rx,
            sender: tx,
            stats,
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
                LoadRequest::Load(id) => Some(self.request_load(id)),
                LoadRequest::Unload => Some(self.request_unload()),
                LoadRequest::Info => Some(self.request_info()),
                LoadRequest::StatsTimer => {
                    self.update_stats();
                    None
                },
            };

            if let Some(response) = result {
                self.sender.send(response).unwrap();
            }
        }
    }

    fn request_load(&mut self, id: FilterID) -> LoadResponse {
        let storage = match FilterStorage::load(id) {
            Some(storage) => storage,
            None => return LoadResponse::Load(
                Err(LoadError::StorageNotExist(id))
            ),
        };

        let result = self.load(&storage);
        LoadResponse::Load(result)
    }

    fn request_unload(&mut self) -> LoadResponse {
        let result = self.unload();
        LoadResponse::Load(result)
    }

    fn request_info(&mut self) -> LoadResponse {
        let info = self.info();
        LoadResponse::Info(info)
    }

    fn info(&mut self) -> Result<Vec<IfaceInfo>, LoadError> {
        let mut info = vec![];

        let ifaces = match get_ifaces() {
            Some(ifaces) => ifaces,
            None => return Err(LoadError::IfacesList),
        };

        for iface in ifaces.iter() {
            let mut filter = None;

            if let Some(loaded_filter) = self.filters.get(iface) {
                filter = Some(loaded_filter.id);
            }

            info.push(IfaceInfo {
                name: iface.clone(),
                filter,
            });
        }

        Ok(info)
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
            self.load_iface(&path, iface, storage.id())?;
        }

        Ok(())
    }

    fn load_iface(&mut self, path: &Path, iface: &str, id: FilterID) -> Result<(), LoadError> {
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
            id,
            object: obj,
            link: link,
        });

        Ok(())
    }

    fn update_stats(&mut self) {
        let mut stats = self.stats.lock().unwrap();

        let cpus = unsafe { libbpf_sys::libbpf_num_possible_cpus() } as usize;
        let total_len = size_of::<u64>() * cpus;
        let mut value = Vec::<u8>::new();
        value.resize(total_len, 0);

        for (iface, filter) in self.filters.iter_mut() {
            let map = filter.object.map_unwrap(compiler::STATS_MAP_NAME);
            let fd = map.fd();
            for stats_key in &[compiler::STATS_KEY_PASS, compiler::STATS_KEY_DROP] {
                let key = stats_key.to_le_bytes();

                assert_eq!(map.value_size(), size_of::<u64>() as u32);

                let result = unsafe {
                    libbpf_sys::bpf_map_lookup_elem(
                        fd,
                        key.as_ptr() as *const ffi::c_void,
                        value.as_mut_ptr() as *mut ffi::c_void
                    )
                };

                if result != 0 {
                    let errno = nix::errno::errno();
                    panic!("error on lookup bpf map element: {}", errno);
                }

                let elem = size_of::<u64>();
                let mut sum = 0;
                for i in 0..cpus {
                    let pos = i * elem;
                    let slice = &value[pos..pos+elem];
                    let cpu_value: u64 = slice.iter().enumerate().map(
                        |(n, b)| (*b as u64) << (8 * n)
                    ).sum();
                    sum += cpu_value;
                }

                stats.register_value(iface, sum, *stats_key).unwrap();
            }
        }
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
