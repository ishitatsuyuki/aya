//! Data structures used to setup and share data with eBPF programs.
//!
//! The eBPF platform provides data structures - maps in eBPF speak - that are
//! used to setup and share data with eBPF programs. When you call
//! [`Bpf::load_file`](crate::Bpf::load_file) or
//! [`Bpf::load`](crate::Bpf::load), all the maps defined in the eBPF code get
//! initialized and can then be accessed using [`Bpf::map`](crate::Bpf::map) and
//! [`Bpf::map_mut`](crate::Bpf::map_mut).
//!
//! # Typed maps
//!
//! The eBPF API includes many map types each supporting different operations.
//! [`Bpf::map`](crate::Bpf::map) and [`Bpf::map_mut`](crate::Bpf::map_mut) always return the
//! opaque [`MapRef`] and [`MapRefMut`] types respectively. Those two types can be converted to
//! *typed maps* using the [`TryFrom`](std::convert::TryFrom) trait. For example:
//!
//! ```no_run
//! # let mut bpf = aya::Bpf::load(&[])?;
//! use std::convert::{TryFrom, TryInto};
//! use aya::maps::SockMap;
//! use aya::programs::SkMsg;
//!
//! let intercept_egress = SockMap::try_from(bpf.map_mut("INTERCEPT_EGRESS")?)?;
//! let prog: &mut SkMsg = bpf.program_mut("intercept_egress_packet").unwrap().try_into()?;
//! prog.load()?;
//! prog.attach(&intercept_egress)?;
//! # Ok::<(), aya::BpfError>(())
//! ```
//!
//! # Maps and `Pod` values
//!
//! Many map operations copy data from kernel space to user space and vice
//! versa. Because of that, all map values must be plain old data and therefore
//! implement the [Pod] trait.
use std::{
    convert::TryFrom, ffi::CString, io, marker::PhantomData, mem, ops::Deref, os::unix::io::RawFd,
    path::Path, ptr,
};
use thiserror::Error;

use crate::{
    generated::bpf_map_type,
    obj,
    sys::{bpf_create_map, bpf_get_object, bpf_map_get_next_key, bpf_pin_object},
    util::nr_cpus,
    Pod,
};

mod map_lock;

pub mod array;
pub mod bloom_filter;
pub mod hash_map;
pub mod lpm_trie;
pub mod perf;
pub mod queue;
pub mod ringbuf;
pub mod sock;
pub mod stack;
pub mod stack_trace;

pub use array::{Array, PerCpuArray, ProgramArray};
pub use hash_map::{HashMap, PerCpuHashMap};
pub use map_lock::*;
pub use perf::PerfEventArray;
pub use queue::Queue;
pub use ringbuf::RingBuf;
pub use sock::{SockHash, SockMap};
pub use stack::Stack;
pub use stack_trace::StackTraceMap;

#[derive(Error, Debug)]
/// Errors occuring from working with Maps
pub enum MapError {
    /// Unable to find the map
    #[error("map `{name}` not found ")]
    MapNotFound {
        /// Map name
        name: String,
    },

    /// Invalid map type encontered
    #[error("invalid map type {map_type}")]
    InvalidMapType {
        /// The map type
        map_type: u32,
    },

    /// Invalid map name encountered
    #[error("invalid map name `{name}`")]
    InvalidName {
        /// The map name
        name: String,
    },

    /// Pin path is invalid
    #[error("invalid map path `{error}`")]
    InvalidPinPath {
        /// The error message
        error: String,
    },

    /// The map has not been created
    #[error("the map has not been created")]
    NotCreated,

    /// The map has already been created
    #[error("the map `{name}` has already been created")]
    AlreadyCreated {
        /// Map name
        name: String,
    },

    /// The map has already been pinned
    #[error("the map `{name}` has already been pinned")]
    AlreadyPinned {
        /// Map name
        name: String,
    },

    /// Failed to create map
    #[error("failed to create map `{name}` with code {code}")]
    CreateError {
        /// Map name
        name: String,
        /// Error code
        code: libc::c_long,
        #[source]
        /// Original io::Error
        io_error: io::Error,
    },

    /// Failed to pin map
    #[error("failed to pin map `{name}` with code {code}")]
    PinError {
        /// Map Name
        name: String,
        /// Error code
        code: libc::c_long,
        #[source]
        /// Original io::Error
        io_error: io::Error,
    },

    /// Invalid key size
    #[error("invalid key size {size}, expected {expected}")]
    InvalidKeySize {
        /// Size encountered
        size: usize,
        /// Size expected
        expected: usize,
    },

    /// Invalid value size
    #[error("invalid value size {size}, expected {expected}")]
    InvalidValueSize {
        /// Size encountered
        size: usize,
        /// Size expected
        expected: usize,
    },

    /// Index is out of bounds
    #[error("the index is {index} but `max_entries` is {max_entries}")]
    OutOfBounds {
        /// Index accessed
        index: u32,
        /// Map size
        max_entries: u32,
    },

    /// Key not found
    #[error("key not found")]
    KeyNotFound,

    /// Element not found
    #[error("element not found")]
    ElementNotFound,

    /// Progam Not Loaded
    #[error("the program is not loaded")]
    ProgramNotLoaded,

    /// Syscall failed
    #[error("the `{call}` syscall failed with code {code}")]
    SyscallError {
        /// Syscall Name
        call: String,
        /// Error code
        code: libc::c_long,
        #[source]
        /// Original io::Error
        io_error: io::Error,
    },

    /// Map is borrowed mutably
    #[error("map `{name}` is borrowed mutably")]
    BorrowError {
        /// Map name
        name: String,
    },

    /// Map is already borrowed
    #[error("map `{name}` is already borrowed")]
    BorrowMutError {
        /// Map name
        name: String,
    },
}

/// A generic handle to a BPF map.
///
/// You should never need to use this unless you're implementing a new map type.
#[derive(Debug)]
pub struct Map {
    pub(crate) obj: obj::Map,
    pub(crate) fd: Option<RawFd>,
    /// Indicates if this map has been pinned to bpffs
    pub pinned: bool,
}

impl Map {
    /// Creates a new map with the provided `name`
    pub fn create(&mut self, name: &str) -> Result<RawFd, MapError> {
        if self.fd.is_some() {
            return Err(MapError::AlreadyCreated { name: name.into() });
        }

        let c_name = CString::new(name).map_err(|_| MapError::InvalidName { name: name.into() })?;

        let fd = bpf_create_map(&c_name, &self.obj.def).map_err(|(code, io_error)| {
            MapError::CreateError {
                name: name.into(),
                code,
                io_error,
            }
        })? as RawFd;

        self.fd = Some(fd);

        Ok(fd)
    }

    pub(crate) fn open_pinned<P: AsRef<Path>>(
        &mut self,
        name: &str,
        path: P,
    ) -> Result<RawFd, MapError> {
        if self.fd.is_some() {
            return Err(MapError::AlreadyCreated { name: name.into() });
        }
        let map_path = path.as_ref().join(name);
        let path_string = match CString::new(map_path.to_str().unwrap()) {
            Ok(s) => s,
            Err(e) => {
                return Err(MapError::InvalidPinPath {
                    error: e.to_string(),
                })
            }
        };
        let fd = bpf_get_object(&path_string).map_err(|(code, io_error)| MapError::PinError {
            name: name.into(),
            code,
            io_error,
        })? as RawFd;

        self.fd = Some(fd);

        Ok(fd)
    }

    /// Returns the [`bpf_map_type`] of this map
    pub fn map_type(&self) -> Result<bpf_map_type, MapError> {
        bpf_map_type::try_from(self.obj.def.map_type)
    }

    pub(crate) fn fd_or_err(&self) -> Result<RawFd, MapError> {
        self.fd.ok_or(MapError::NotCreated)
    }

    pub(crate) fn pin<P: AsRef<Path>>(&mut self, name: &str, path: P) -> Result<(), MapError> {
        if self.pinned {
            return Err(MapError::AlreadyPinned { name: name.into() });
        }
        let map_path = path.as_ref().join(name);
        let fd = self.fd_or_err()?;
        let path_string = CString::new(map_path.to_string_lossy().into_owned()).map_err(|e| {
            MapError::InvalidPinPath {
                error: e.to_string(),
            }
        })?;
        bpf_pin_object(fd, &path_string).map_err(|(code, io_error)| MapError::SyscallError {
            call: "BPF_OBJ_PIN".to_string(),
            code,
            io_error,
        })?;
        self.pinned = true;
        Ok(())
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        // TODO: Replace this with an OwnedFd once that is stabilized.
        if let Some(fd) = self.fd.take() {
            unsafe { libc::close(fd) };
        }
    }
}

/// An iterable map
pub trait IterableMap<K: Pod, V> {
    /// Get a generic map handle
    fn map(&self) -> &Map;

    /// Get the value for the provided `key`
    fn get(&self, key: &K) -> Result<V, MapError>;
}

/// Iterator returned by `map.keys()`.
pub struct MapKeys<'coll, K: Pod> {
    map: &'coll Map,
    err: bool,
    key: Option<K>,
}

impl<'coll, K: Pod> MapKeys<'coll, K> {
    fn new(map: &'coll Map) -> MapKeys<'coll, K> {
        MapKeys {
            map,
            err: false,
            key: None,
        }
    }
}

impl<K: Pod> Iterator for MapKeys<'_, K> {
    type Item = Result<K, MapError>;

    fn next(&mut self) -> Option<Result<K, MapError>> {
        if self.err {
            return None;
        }

        let fd = match self.map.fd_or_err() {
            Ok(fd) => fd,
            Err(e) => {
                self.err = true;
                return Some(Err(e));
            }
        };

        match bpf_map_get_next_key(fd, self.key.as_ref()) {
            Ok(Some(key)) => {
                self.key = Some(key);
                Some(Ok(key))
            }
            Ok(None) => {
                self.key = None;
                None
            }
            Err((code, io_error)) => {
                self.err = true;
                Some(Err(MapError::SyscallError {
                    call: "bpf_map_get_next_key".to_owned(),
                    code,
                    io_error,
                }))
            }
        }
    }
}

/// Iterator returned by `map.iter()`.
pub struct MapIter<'coll, K: Pod, V, I: IterableMap<K, V>> {
    keys: MapKeys<'coll, K>,
    map: &'coll I,
    _v: PhantomData<V>,
}

impl<'coll, K: Pod, V, I: IterableMap<K, V>> MapIter<'coll, K, V, I> {
    fn new(map: &'coll I) -> MapIter<'coll, K, V, I> {
        MapIter {
            keys: MapKeys::new(map.map()),
            map,
            _v: PhantomData,
        }
    }
}

impl<K: Pod, V, I: IterableMap<K, V>> Iterator for MapIter<'_, K, V, I> {
    type Item = Result<(K, V), MapError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.keys.next() {
                Some(Ok(key)) => match self.map.get(&key) {
                    Ok(value) => return Some(Ok((key, value))),
                    Err(MapError::KeyNotFound) => continue,
                    Err(e) => return Some(Err(e)),
                },
                Some(Err(e)) => return Some(Err(e)),
                None => return None,
            }
        }
    }
}

impl TryFrom<u32> for bpf_map_type {
    type Error = MapError;

    fn try_from(map_type: u32) -> Result<Self, Self::Error> {
        use bpf_map_type::*;
        Ok(match map_type {
            x if x == BPF_MAP_TYPE_UNSPEC as u32 => BPF_MAP_TYPE_UNSPEC,
            x if x == BPF_MAP_TYPE_HASH as u32 => BPF_MAP_TYPE_HASH,
            x if x == BPF_MAP_TYPE_ARRAY as u32 => BPF_MAP_TYPE_ARRAY,
            x if x == BPF_MAP_TYPE_PROG_ARRAY as u32 => BPF_MAP_TYPE_PROG_ARRAY,
            x if x == BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 => BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            x if x == BPF_MAP_TYPE_PERCPU_HASH as u32 => BPF_MAP_TYPE_PERCPU_HASH,
            x if x == BPF_MAP_TYPE_PERCPU_ARRAY as u32 => BPF_MAP_TYPE_PERCPU_ARRAY,
            x if x == BPF_MAP_TYPE_STACK_TRACE as u32 => BPF_MAP_TYPE_STACK_TRACE,
            x if x == BPF_MAP_TYPE_CGROUP_ARRAY as u32 => BPF_MAP_TYPE_CGROUP_ARRAY,
            x if x == BPF_MAP_TYPE_LRU_HASH as u32 => BPF_MAP_TYPE_LRU_HASH,
            x if x == BPF_MAP_TYPE_LRU_PERCPU_HASH as u32 => BPF_MAP_TYPE_LRU_PERCPU_HASH,
            x if x == BPF_MAP_TYPE_LPM_TRIE as u32 => BPF_MAP_TYPE_LPM_TRIE,
            x if x == BPF_MAP_TYPE_BLOOM_FILTER as u32 => BPF_MAP_TYPE_BLOOM_FILTER,
            x if x == BPF_MAP_TYPE_ARRAY_OF_MAPS as u32 => BPF_MAP_TYPE_ARRAY_OF_MAPS,
            x if x == BPF_MAP_TYPE_HASH_OF_MAPS as u32 => BPF_MAP_TYPE_HASH_OF_MAPS,
            x if x == BPF_MAP_TYPE_DEVMAP as u32 => BPF_MAP_TYPE_DEVMAP,
            x if x == BPF_MAP_TYPE_SOCKMAP as u32 => BPF_MAP_TYPE_SOCKMAP,
            x if x == BPF_MAP_TYPE_CPUMAP as u32 => BPF_MAP_TYPE_CPUMAP,
            x if x == BPF_MAP_TYPE_XSKMAP as u32 => BPF_MAP_TYPE_XSKMAP,
            x if x == BPF_MAP_TYPE_SOCKHASH as u32 => BPF_MAP_TYPE_SOCKHASH,
            x if x == BPF_MAP_TYPE_CGROUP_STORAGE as u32 => BPF_MAP_TYPE_CGROUP_STORAGE,
            x if x == BPF_MAP_TYPE_REUSEPORT_SOCKARRAY as u32 => BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
            x if x == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE as u32 => {
                BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
            }
            x if x == BPF_MAP_TYPE_QUEUE as u32 => BPF_MAP_TYPE_QUEUE,
            x if x == BPF_MAP_TYPE_STACK as u32 => BPF_MAP_TYPE_STACK,
            x if x == BPF_MAP_TYPE_SK_STORAGE as u32 => BPF_MAP_TYPE_SK_STORAGE,
            x if x == BPF_MAP_TYPE_DEVMAP_HASH as u32 => BPF_MAP_TYPE_DEVMAP_HASH,
            x if x == BPF_MAP_TYPE_STRUCT_OPS as u32 => BPF_MAP_TYPE_STRUCT_OPS,
            x if x == BPF_MAP_TYPE_RINGBUF as u32 => BPF_MAP_TYPE_RINGBUF,
            x if x == BPF_MAP_TYPE_INODE_STORAGE as u32 => BPF_MAP_TYPE_INODE_STORAGE,
            x if x == BPF_MAP_TYPE_TASK_STORAGE as u32 => BPF_MAP_TYPE_TASK_STORAGE,
            _ => return Err(MapError::InvalidMapType { map_type }),
        })
    }
}
pub(crate) struct PerCpuKernelMem {
    bytes: Vec<u8>,
}

impl PerCpuKernelMem {
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
}

/// A slice of per-CPU values.
///
/// Used by maps that implement per-CPU storage like [`PerCpuHashMap`].
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let bpf = aya::Bpf::load(&[])?;
/// use aya::maps::PerCpuValues;
/// use aya::util::nr_cpus;
/// use std::convert::TryFrom;
///
/// let values = PerCpuValues::try_from(vec![42u32; nr_cpus()?])?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
pub struct PerCpuValues<T: Pod> {
    values: Box<[T]>,
}

impl<T: Pod> TryFrom<Vec<T>> for PerCpuValues<T> {
    type Error = io::Error;

    fn try_from(values: Vec<T>) -> Result<Self, Self::Error> {
        let nr_cpus = nr_cpus()?;
        if values.len() != nr_cpus {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not enough values ({}), nr_cpus: {}", values.len(), nr_cpus),
            ));
        }
        Ok(PerCpuValues {
            values: values.into_boxed_slice(),
        })
    }
}

impl<T: Pod> PerCpuValues<T> {
    pub(crate) fn alloc_kernel_mem() -> Result<PerCpuKernelMem, io::Error> {
        let value_size = (mem::size_of::<T>() + 7) & !7;
        Ok(PerCpuKernelMem {
            bytes: vec![0u8; nr_cpus()? * value_size],
        })
    }

    pub(crate) unsafe fn from_kernel_mem(mem: PerCpuKernelMem) -> PerCpuValues<T> {
        let mem_ptr = mem.bytes.as_ptr() as usize;
        let value_size = (mem::size_of::<T>() + 7) & !7;
        let mut values = Vec::new();
        let mut offset = 0;
        while offset < mem.bytes.len() {
            values.push(ptr::read_unaligned((mem_ptr + offset) as *const _));
            offset += value_size;
        }

        PerCpuValues {
            values: values.into_boxed_slice(),
        }
    }

    pub(crate) fn build_kernel_mem(&self) -> Result<PerCpuKernelMem, io::Error> {
        let mut mem = PerCpuValues::<T>::alloc_kernel_mem()?;
        let mem_ptr = mem.as_mut_ptr() as usize;
        let value_size = (mem::size_of::<T>() + 7) & !7;
        for i in 0..self.values.len() {
            unsafe { ptr::write_unaligned((mem_ptr + i * value_size) as *mut _, self.values[i]) };
        }

        Ok(mem)
    }
}

impl<T: Pod> Deref for PerCpuValues<T> {
    type Target = Box<[T]>;

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

#[cfg(test)]
mod tests {
    use libc::EFAULT;

    use crate::{
        bpf_map_def,
        generated::{bpf_cmd, bpf_map_type::BPF_MAP_TYPE_HASH},
        obj::MapKind,
        sys::{override_syscall, Syscall},
    };

    use super::*;

    fn new_obj_map() -> obj::Map {
        obj::Map {
            def: bpf_map_def {
                map_type: BPF_MAP_TYPE_HASH as u32,
                key_size: 4,
                value_size: 4,
                max_entries: 1024,
                ..Default::default()
            },
            section_index: 0,
            symbol_index: 0,
            data: Vec::new(),
            kind: MapKind::Other,
        }
    }

    fn new_map() -> Map {
        Map {
            obj: new_obj_map(),
            fd: None,
            pinned: false,
        }
    }

    #[test]
    fn test_create() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(42),
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        let mut map = new_map();
        assert!(matches!(map.create("foo"), Ok(42)));
        assert_eq!(map.fd, Some(42));
        assert!(matches!(
            map.create("foo"),
            Err(MapError::AlreadyCreated { .. })
        ));
    }

    #[test]
    fn test_create_failed() {
        override_syscall(|_| Err((-42, io::Error::from_raw_os_error(EFAULT))));

        let mut map = new_map();
        let ret = map.create("foo");
        assert!(matches!(ret, Err(MapError::CreateError { .. })));
        if let Err(MapError::CreateError {
            name,
            code,
            io_error,
        }) = ret
        {
            assert_eq!(name, "foo");
            assert_eq!(code, -42);
            assert_eq!(io_error.raw_os_error(), Some(EFAULT));
        }
        assert_eq!(map.fd, None);
    }
}
