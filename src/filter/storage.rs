use rand::Rng;

use std::{io::Error as IOError, path::PathBuf};

const STORAGE_PATH: &str = "/var/lib/xnf/filters";
const CURRENT_PATH: &str = "/var/lib/xnf/current";

pub type FilterID = u64;

pub struct FilterStorage {
    id: FilterID,
}

impl FilterStorage {
    pub fn new() -> Result<Self, IOError> {
        let mut rng = rand::thread_rng();
        let mut id;

        loop {
            id = rng.gen();
            if Self::load(id).is_none() {
                break;
            }
        }

        let path = filter_path(&id);
        std::fs::create_dir_all(path)?;

        let storage = Self::load(id).unwrap();
        Ok(storage)
    }

    pub fn load(id: FilterID) -> Option<Self> {
        let path = filter_path(&id);
        if !path.is_dir() {
            return None;
        }

        let storage = Self {
            id,
        };
        Some(storage)
    }

    pub fn load_current() -> Option<Self> {
        let path = PathBuf::from(CURRENT_PATH);
        let real_path = match std::fs::read_link(&path) {
            Ok(path) => path,
            Err(_) => return None,
        };

        let expected_path = PathBuf::from(STORAGE_PATH);

        match real_path.parent() {
            Some(parent) => {
                if parent != expected_path {
                    return None;
                }
            },
            None => return None,
        }

        let name = real_path.file_name().unwrap().to_str().unwrap();
        let id: FilterID = match FilterID::from_str_radix(name, 16) {
            Ok(id) => id,
            Err(_) => return None,
        };

        let storage = Self {
            id,
        };

        Some(storage)
    }

    pub fn id(&self) -> FilterID {
        self.id
    }

    pub fn get_object(&self, iface: Option<&str>) -> Option<PathBuf> {
        let path = self.build_object_path(iface);

        if !path.is_file() {
            return None;
        }

        Some(path)
    }

    pub fn save_object(&self, iface: Option<&str>) -> Option<PathBuf> {
        let path = self.build_object_path(iface);

        if path.is_file() {
            return None;
        }

        Some(path)
    }

    pub fn mark_current(&self) -> Result<(), IOError> {
        let filter_path = filter_path(&self.id);
        let current_link = PathBuf::from(CURRENT_PATH);
        Self::remove_mark()?;

        std::os::unix::fs::symlink(&filter_path, &current_link)?;

        Ok(())
    }

    pub fn remove_mark() -> Result<(), IOError> {
        let current_link = PathBuf::from(CURRENT_PATH);
        if current_link.exists() {
            std::fs::remove_file(&current_link)?;
        }

        Ok(())
    }

    fn build_object_path(&self, iface: Option<&str>) -> PathBuf {
        let mut path = filter_path(&self.id);

        if let Some(iface) = iface {
            let name = format!("iface_{}.o", iface);
            path.push(name);
        } else {
            path.push("iface.so");
        }

        path
    }
}

pub fn filter_name(id: &FilterID) -> String {
    format!("{:016x}", id)
}

fn filter_path(id: &FilterID) -> PathBuf {
    let mut path = PathBuf::from(STORAGE_PATH);

    let hex = filter_name(id);
    path.push(hex);

    path
}
