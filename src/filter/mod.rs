use libbpf_rs as bpf;
use nix::{self, sys::socket::SockAddr};

use std::path::Path;

#[derive(Debug)]
pub enum LoadError {
    IfaceNotExist(String),
    Open(String),
    Load(String),
    Attach(String),
}

pub fn load(iface_name: &str, path: &Path, debug: bool) -> Result<(), LoadError> {
    let ifindex = match get_ifindex(iface_name) {
        Some(index) => index,
        None => return Err(LoadError::IfaceNotExist(iface_name.to_string())),
    };

    let mut builder = bpf::ObjectBuilder::default();
    builder.debug(debug);

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

    let _link = match prog.attach_xdp(ifindex as i32) {
        Ok(link) => link,
        Err(error) => return Err(
            LoadError::Attach(format!("{}", error))
        ),
    };

    Ok(())
}

fn get_ifindex(iface_name: &str) -> Option<usize> {
    let ifaces;
    match nix::ifaddrs::getifaddrs() {
        Ok(new_ifaces) => ifaces = new_ifaces,
        Err(_) => return None,
    }

    for iface in ifaces {
        if iface.interface_name == iface_name {
            if let Some(SockAddr::Link(addr)) = iface.address {
                return Some(addr.ifindex());
            }
        }
    }

    None
}
