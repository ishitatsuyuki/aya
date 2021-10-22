//! A [ring buffer map][ringbuf] that may be used to receive events from eBPF programs.
//! As of Linux 5.8, this is the preferred way to transfer per-event data from eBPF
//! programs to userspace.
//!
//! [ringbuf]: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html

use std::{
    convert::TryFrom,
    io,
    ops::DerefMut,
    os::unix::prelude::AsRawFd,
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};

use libc::{munmap, sysconf, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, _SC_PAGESIZE};
use thiserror::Error;

use crate::{
    generated::{
        bpf_map_type::BPF_MAP_TYPE_RINGBUF, BPF_RINGBUF_BUSY_BIT, BPF_RINGBUF_DISCARD_BIT,
        BPF_RINGBUF_HDR_SZ,
    },
    maps::{Map, MapError, MapRefMut},
    sys::mmap,
};

/// Ring buffer error.
#[derive(Error, Debug)]
pub enum RingBufferError {
    /// `mmap`-ping the consumer buffer failed.
    #[error("consumer mmap failed: {io_error}")]
    ConsumerMMapError {
        /// The wrapped IO error.
        #[source]
        io_error: io::Error,
    },

    /// `mmap`-ping the produer buffer failed.
    #[error("consumer mmap failed: {io_error}")]
    ProducerMMapError {
        /// The wrapped IO error.
        #[source]
        io_error: io::Error,
    },

    /// An error occurred related to the inner map.
    #[error(transparent)]
    MapError(#[from] MapError),

    /// An IO error occurred.
    #[error(transparent)]
    IOError(#[from] io::Error),
}

/// A map that can be used to receive events from eBPF programs.
///
/// This is similar to [`PerfEventArray`], but different in a few ways:
/// * It's shared across all CPUs, which allows a strong ordering between events. It also makes the
///   buffer creation easier.
/// * Data notifications are delivered for every event instead of being sampled for every N event;
///   the eBPF program can also control notification delivery if sampling is desired for performance reasons.
/// * On the eBPF side, it supports the reverse-commit pattern where the event can be directly
///   written into the ring without copying from a temporary location.
/// * Dropped sample notifications goes to the eBPF program as the return value of `reserve`/`output`,
///   and not the userspace reader. This might require extra code to handle, but allows for more
///   flexible schemes to handle dropped samples.
///
/// To receive events you need to:
/// * call [`RingBuf::try_from`]
/// * poll the returned [`RingBuf`] to be notified when events are inserted in the buffer
/// * call [`RingBuf::process_ring`] to read the events
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.8.
///
/// # Examples
///
/// The following example shows how to read samples as well as using an async runtime
/// to wait for samples to be ready:
///
/// ```no_run
/// # use aya::maps::{Map, RingBuf};
/// # use std::ops::DerefMut;
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #    #[error(transparent)]
/// #    IO(#[from] std::io::Error),
/// #    #[error(transparent)]
/// #    Map(#[from] aya::maps::MapError),
/// #    #[error(transparent)]
/// #    Bpf(#[from] aya::BpfError),
/// #    #[error(transparent)]
/// #    RingBuf(#[from] aya::maps::ringbuf::RingBufferError),
/// # }
/// # struct Poll<T: DerefMut<Target=Map>>(RingBuf<T>);
/// # impl<T: DerefMut<Target=Map>> Poll<T> {
/// #    fn new(inner: RingBuf<T>) -> Self { Self (inner) }
/// #    fn readable(&mut self) {}
/// #    fn get_mut(&mut self) -> &mut RingBuf<T> { &mut self.0 }
/// # }
/// # let bpf = aya::Bpf::load(&[])?;
/// use std::convert::{TryFrom, TryInto};
///
/// let mut ring = RingBuf::try_from(bpf.map_mut("EVENTS")?)?;
///
/// // Poll would be a struct that wraps `AsRawFd`.
/// let mut poll = Poll::new(ring);
/// loop {
///     // readable() should be a function that waits ring's fd to be readable.
///     // If you're using an async library, you can .await here
///     poll.readable();
///
///     poll.get_mut().process_ring(&mut |data| {
///         // Do something with the data bytes
///     });
/// }
/// # Ok::<(), Error>(())
/// ```
///
/// [`PerfEventArray`]: crate::maps::PerfEventArray
#[doc(alias = "BPF_MAP_TYPE_RINGBUF")]
pub struct RingBuf<T: DerefMut<Target = Map>> {
    _map: T,
    map_fd: i32,
    data_ptr: *mut u8,
    consumer_pos_ptr: *mut AtomicUsize,
    producer_pos_ptr: *mut AtomicUsize,
    page_size: usize,
    mask: usize,
}

impl<T: DerefMut<Target = Map>> RingBuf<T> {
    pub(crate) fn new(map: T) -> Result<Self, RingBufferError> {
        // Check that the map is a ringbuf
        let map_type = map.obj.map_type();
        if map_type != BPF_MAP_TYPE_RINGBUF as u32 {
            return Err(MapError::InvalidMapType { map_type }.into());
        }

        // Determine page_size, map_fd, and set mask to map size - 1
        let page_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;
        let map_fd = map.fd_or_err().map_err(RingBufferError::from)?;
        let mask = (map.obj.max_entries() - 1) as usize;

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

        // From kernel/bpf/ringbuf.c:
        // Each data page is mapped twice to allow "virtual"
        // continuous read of samples wrapping around the end of ring
        // buffer area:
        // ------------------------------------------------------
        // | meta pages |  real data pages  |  same data pages  |
        // ------------------------------------------------------
        // |            | 1 2 3 4 5 6 7 8 9 | 1 2 3 4 5 6 7 8 9 |
        // ------------------------------------------------------
        // |            | TA             DA | TA             DA |
        // ------------------------------------------------------
        //                               ^^^^^^^
        //                                  |
        // Here, no need to worry about special handling of wrapped-around
        // data due to double-mapped data pages. This works both in kernel and
        // when mmap()'ed in user-space, simplifying both kernel and
        // user-space implementations significantly.
        let producer_pages = unsafe {
            mmap(
                ptr::null_mut(),
                page_size + 2 * (mask + 1),
                PROT_READ,
                MAP_SHARED,
                map_fd,
                page_size as _,
            )
        };
        if producer_pages == MAP_FAILED {
            return Err(RingBufferError::ProducerMMapError {
                io_error: io::Error::last_os_error(),
            });
        }

        Ok(RingBuf {
            _map: map,
            map_fd,
            data_ptr: unsafe { (producer_pages as *mut u8).add(page_size) },
            consumer_pos_ptr: consumer_page as *mut _,
            producer_pos_ptr: producer_pages as *mut _,
            page_size,
            mask,
        })
    }

    /// Retrieve an event from the ring, pass it to the callback, mark it as consumed, then repeat.
    ///
    /// Returns when there's no more events.
    pub fn process_ring(&mut self, callback: &mut impl FnMut(&[u8])) {
        self.process_ring_impl(&mut |buf| {
            callback(buf);
            Ok(())
        })
        .unwrap()
    }

    /// Same as [`RingBuf::process_ring`], but the callback can return `Err` in order to stop early.
    ///
    /// Returns when either the callback returns an Err or there's no more events.
    pub fn process_ring_fallible<E>(
        &mut self,
        callback: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut err = None;
        self.process_ring_impl(&mut |buf| {
            #[allow(clippy::unused_unit)] // Removing unit makes the code harder to comprehend
            callback(buf).map_err(|e| {
                err = Some(e);
                ()
            })
        })
        .map_err(|_| err.unwrap())
    }

    fn process_ring_impl(
        &mut self,
        callback: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
    ) -> Result<(), ()> {
        // Relaxed since stores to consumer_pos is race free (stores done on same thread or migrated with acquire-release).
        let mut consumer_pos = unsafe { (*self.consumer_pos_ptr).load(Ordering::Relaxed) };
        loop {
            let mut got_new = false;

            // Need to be SeqCst to match the SeqCst store below (otherwise read-after-write can be reordered).
            let producer_pos = unsafe { (*self.producer_pos_ptr).load(Ordering::SeqCst) };
            while consumer_pos < producer_pos {
                let sample_head = unsafe { self.data_ptr.add(consumer_pos as usize & self.mask) };
                let len_and_flags = unsafe { *(sample_head as *mut u32) };

                // The sample has not been committed yet, so bail
                if (len_and_flags as usize & BPF_RINGBUF_BUSY_BIT as usize) != 0 {
                    return Ok(());
                }

                // Got a new sample
                got_new = true;
                consumer_pos += roundup_len(len_and_flags) as usize;

                if (len_and_flags & BPF_RINGBUF_DISCARD_BIT) == 0 {
                    // Coerce the sample into a &[u8]
                    let sample_ptr = unsafe { sample_head.add(BPF_RINGBUF_HDR_SZ as usize) };
                    let sample = unsafe {
                        std::slice::from_raw_parts(sample_ptr as *mut u8, len_and_flags as usize)
                    };

                    if let Err(e) = callback(sample) {
                        // Store new consumer position and forward error from callback.
                        // See below for the SeqCst requirement.
                        unsafe { (*self.consumer_pos_ptr).store(consumer_pos, Ordering::SeqCst) };
                        return Err(e);
                    };
                }

                // Store new consumer position.
                // This store as well as the producer pointer store in the kernel has to participate
                // in a total ordering (SeqCst) in order to avoid loss notification anomalies.
                // See https://github.com/aya-rs/aya/pull/294 for details.
                unsafe { (*self.consumer_pos_ptr).store(consumer_pos, Ordering::SeqCst) };
            }

            if !got_new {
                break;
            }
        }

        Ok(())
    }
}

impl<T: DerefMut<Target = Map>> Drop for RingBuf<T> {
    fn drop(&mut self) {
        if !self.consumer_pos_ptr.is_null() {
            // SAFETY: `consumer_pos` is not null and consumer page is not null and
            // consumer page was mapped with size `self.page_size`
            unsafe { munmap(self.consumer_pos_ptr as *mut _, self.page_size) };
        }

        if !self.producer_pos_ptr.is_null() {
            // SAFETY: `producer_pos` is not null and producer pages were mapped with size
            // `self.page_size + 2 * (self.mask + 1)`
            unsafe {
                munmap(
                    self.producer_pos_ptr as *mut _,
                    self.page_size + 2 * (self.mask + 1),
                )
            };
        }
    }
}

impl<T: DerefMut<Target = Map>> AsRawFd for RingBuf<T> {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.map_fd
    }
}

impl TryFrom<MapRefMut> for RingBuf<MapRefMut> {
    type Error = RingBufferError;

    fn try_from(a: MapRefMut) -> Result<RingBuf<MapRefMut>, RingBufferError> {
        RingBuf::new(a)
    }
}

/// Round up a `len` to the nearest 8 byte alignment, adding BPF_RINGBUF_HDR_SZ and
/// clearing out the upper two bits of `len`.
pub(crate) fn roundup_len(len: u32) -> u32 {
    let mut len = len;
    // clear out the upper two bits (busy and discard)
    len &= 0x3fffffff;
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
}
