//! A [ring buffer map][ringbuf] that may be used to receive events from eBPF programs.
//! As of Linux 5.8, this is the preferred way to transfer per-event data from eBPF
//! programs to userspace.
//!
//! [ringbuf]: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html

use std::{
    io,
    ops::DerefMut,
    os::unix::prelude::AsRawFd,
    ptr,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Arc,
    },
};

use libc::{
    c_ulong, c_void, munmap, sysconf, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, _SC_PAGESIZE,
};
use thiserror::Error;

use crate::{
    generated::{
        bpf_map_type::BPF_MAP_TYPE_RINGBUF, BPF_RINGBUF_BUSY_BIT, BPF_RINGBUF_DISCARD_BIT,
        BPF_RINGBUF_HDR_SZ,
    },
    maps::{Map, MapError},
    sys::mmap,
};

/// Ring buffer error.
#[derive(Error, Debug)]
pub enum RingBufferError {
    // TODO: Write doucmentation
    #[error("invalid page count {page_count}, the value must be a power of two")]
    InvalidPageCount { page_count: usize },

    /// `mmap`-ping the consumer buffer failed.
    #[error("consumer mmap failed: {io_error}")]
    ConsumerMMapError {
        #[source]
        io_error: io::Error,
    },

    /// `mmap`-ping the produer buffer failed.
    #[error("consumer mmap failed: {io_error}")]
    ProducerMMapError {
        #[source]
        io_error: io::Error,
    },

    /// An error occurred related to the inner map.
    #[error(transparent)]
    MapError(#[from] MapError),

    /// An IO error occurred.
    #[error(transparent)]
    IOError(#[from] io::Error),

    /// An error occurred in a per-event callback.
    #[error(transparent)]
    CallbackError(#[from] CallbackError),
}

/// A per-event callback error.
#[derive(Error, Debug)]
pub enum CallbackError {
    #[error(transparent)]
    Error(#[from] anyhow::Error),
}

// TODO: Write documentation
#[doc(alias = "BPF_MAP_TYPE_RINGBUF")]
pub struct RingBuf<T: DerefMut<Target = Map>> {
    rings: Vec<Ring<T>>,
}

impl<T: DerefMut<Target = Map>> RingBuf<T> {
    pub fn new() -> Self {
        RingBuf { rings: vec![] }
    }

    // TODO: Write documentation
    pub fn add<Callback>(&mut self, map: T, callback: Callback) -> Result<(), RingBufferError>
    where
        Callback: FnMut(&[u8]) -> Result<(), CallbackError> + 'static,
    {
        self.rings.push(Ring::new(map, callback)?);
        Ok(())
    }

    /// Consume all underlying ring buffers without polling. This is useful when the
    /// lowest possible latency is desired, at the cost of possibly wasted CPU cycles.
    ///
    /// In general, users should prefer using [`RingBuf::rings_mut`] and polling each
    /// buffer individually.
    pub fn consume(&mut self) -> Result<u64, CallbackError> {
        let mut count = 0;

        for ring in &mut self.rings {
            match ring.process_ring() {
                Ok(c) => count += c,
                Err(e) => return Err(e),
            }
        }

        Ok(count)
    }

    /// Returns an iterator over the underlying ring buffers.
    /// This is useful for registering a buffer's file descriptor with a polling library
    /// like [epoll] or [mio] and processing events on a per-buffer basis.
    ///
    /// [epoll]: https://docs.rs/epoll
    /// [mio]: https://docs.rs/mio
    pub fn rings_mut<'a>(&'a mut self) -> impl Iterator<Item = &mut Ring<T>> + 'a {
        self.rings.iter_mut()
    }
}

// TODO: Write documentation
pub struct Ring<T: DerefMut<Target = Map>> {
    _map: Arc<T>,
    map_fd: i32,
    data: AtomicPtr<c_void>,
    consumer_pos: AtomicPtr<c_ulong>,
    producer_pos: AtomicPtr<c_ulong>,
    page_size: usize,
    mask: usize,
    callback: Box<dyn FnMut(&[u8]) -> Result<(), CallbackError>>,
}

impl<T: DerefMut<Target = Map>> Ring<T> {
    // TODO: Write documentation
    pub(crate) fn new<Callback>(map: T, callback: Callback) -> Result<Self, RingBufferError>
    where
        Callback: FnMut(&[u8]) -> Result<(), CallbackError> + 'static,
    {
        // Check that the map is a ringbuf
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_RINGBUF as u32 {
            return Err(MapError::InvalidMapType { map_type }.into());
        }

        // Determine page_size, map_fd, and set mask to map size - 1
        let page_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;
        let map_fd = map.fd_or_err().map_err(RingBufferError::from)?;
        let mask = (map.obj.def.max_entries - 1) as usize;

        // Map writable consumer page
        let consumer_page = unsafe {
            mmap(
                ptr::null_mut(),
                page_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                map_fd,
                0,
            )
        };
        if consumer_page == MAP_FAILED {
            return Err(RingBufferError::ConsumerMMapError {
                io_error: io::Error::last_os_error(),
            });
        }

        // Map read-only producer page and data pages. Like in [libbpf], we map twice as big
        // as the data size to allow reading samples that wrap around the end of the ring
        // buffer.
        //
        // [libbpf]: https://github.com/libbpf/libbpf/blob/92c1e61a605410b16d6330fdd4a7a4e03add86d4/src/ringbuf.c#L110-L115
        let producer_pages = unsafe {
            mmap(
                ptr::null_mut(),
                page_size + 2 * (mask + 1),
                PROT_READ,
                MAP_SHARED,
                map_fd,
                page_size as i64,
            )
        };
        if producer_pages == MAP_FAILED {
            return Err(RingBufferError::ProducerMMapError {
                io_error: io::Error::last_os_error(),
            });
        }

        Ok(Ring {
            _map: Arc::new(map),
            map_fd,
            data: AtomicPtr::new(unsafe { producer_pages.add(page_size) }),
            consumer_pos: AtomicPtr::new(consumer_page as *mut _),
            producer_pos: AtomicPtr::new(producer_pages as *mut _),
            page_size,
            mask,
            callback: Box::new(callback),
        })
    }

    /// Process all available events in the ring. This is pretty much a 1-1
    /// reimplementation of what [libbpf] is doing.
    ///
    /// FIXME: This isn't working properly, needs debugging.
    ///
    /// [libbpf]: https://github.com/libbpf/libbpf/blob/ebf17ac6288e668b5e5999b74c970498ad311bd2/src/ringbuf.c#L205-L246
    pub(crate) fn process_ring(&mut self) -> Result<u64, CallbackError> {
        let mut count = 0u64;
        let mut got_new;
        let mut len;
        let len_ptr = AtomicPtr::<u32>::new(ptr::null_mut());

        let mut consumer_pos = unsafe { *self.consumer_pos.load(Ordering::SeqCst) };
        loop {
            got_new = false;

            let produer_pos = unsafe { *self.producer_pos.load(Ordering::SeqCst) };
            while consumer_pos < produer_pos {
                len_ptr.store(
                    unsafe {
                        self.data
                            .load(Ordering::SeqCst)
                            .add(consumer_pos as usize & self.mask)
                            as *mut _
                    },
                    Ordering::SeqCst,
                );
                len = unsafe { *len_ptr.load(Ordering::SeqCst) };

                // The sample has not been comitted yet, so bail
                if (len as usize & BPF_RINGBUF_BUSY_BIT as usize) != 0 {
                    return Ok(count);
                }

                // Got a new sample
                got_new = true;
                consumer_pos += roundup_len(len) as u64;

                if (len & BPF_RINGBUF_DISCARD_BIT) == 0 {
                    // Coerce the sample into a &[u8]
                    let sample_ptr = unsafe {
                        len_ptr
                            .load(Ordering::SeqCst)
                            .add(BPF_RINGBUF_HDR_SZ as usize)
                    };
                    let sample =
                        unsafe { std::slice::from_raw_parts(sample_ptr as *mut u8, len as usize) };

                    if let Err(e) = (*self.callback)(sample) {
                        // Store new consumer position and forward error from callback
                        self.consumer_pos
                            .store(consumer_pos as *mut _, Ordering::SeqCst);
                        return Err(e);
                    };
                    count += 1;
                }

                // Store new consumer position
                self.consumer_pos
                    .store(consumer_pos as *mut _, Ordering::SeqCst);
            }

            if !got_new {
                break;
            }
        }

        Ok(count)
    }
}

impl<T: DerefMut<Target = Map>> Drop for Ring<T> {
    fn drop(&mut self) {
        let producer_pos = self.producer_pos.load(Ordering::SeqCst);
        let consumer_pos = self.producer_pos.load(Ordering::SeqCst);

        if !consumer_pos.is_null() {
            // SAFETY: `consumer_pos` is not null and consumer page is not null and
            // consumer page was mapped with size `self.page_size`
            unsafe { munmap(consumer_pos as *mut _, self.page_size) };
            self.consumer_pos.swap(ptr::null_mut(), Ordering::SeqCst);
        }

        if !producer_pos.is_null() {
            // SAFETY: `producer_pos` is not null and producer pages were mapped with size
            // `self.page_size + 2 * (self.mask + 1)`
            unsafe { munmap(producer_pos as *mut _, self.page_size + 2 * (self.mask + 1)) };
            self.producer_pos.swap(ptr::null_mut(), Ordering::SeqCst);
        }
    }
}

impl<T: DerefMut<Target = Map>> AsRawFd for Ring<T> {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.map_fd
    }
}

/// Round up a `len` to the nearest 8 byte alignment, adding BPF_RINGBUF_HDR_SZ and
/// clearing out the upper two bits of `len`.
pub(crate) fn roundup_len(len: u32) -> u32 {
    let mut len = len;
    // clear out the upper two bits (busy and discard)
    len <<= 2;
    len >>= 2;
    // add the size of the header prefix
    len += BPF_RINGBUF_HDR_SZ;
    // round to up to next multiple of 8
    (len + 7) & !7
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundup_len() {
        // should always round up to nearest 8 byte alignment + BPF_RINGBUF_HDR_SZ
        assert_eq!(roundup_len(0), BPF_RINGBUF_HDR_SZ);
        assert_eq!(roundup_len(1), BPF_RINGBUF_HDR_SZ + 8);
        assert_eq!(roundup_len(8), BPF_RINGBUF_HDR_SZ + 8);
        assert_eq!(roundup_len(9), BPF_RINGBUF_HDR_SZ + 16);
        // should discard the upper two bits of len
        assert_eq!(
            roundup_len(0 | (BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT)),
            BPF_RINGBUF_HDR_SZ
        );
    }

    #[test]
    fn test_invalid_page_count() {}
}
