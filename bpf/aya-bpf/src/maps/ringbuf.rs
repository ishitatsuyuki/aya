use core::mem;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_RINGBUF},
    helpers::{
        bpf_ringbuf_discard, bpf_ringbuf_output, bpf_ringbuf_query, bpf_ringbuf_reserve,
        bpf_ringbuf_submit,
    },
    maps::PinningType,
};

#[repr(transparent)]
pub struct RingBuf {
    def: bpf_map_def,
}

impl RingBuf {
    // TODO: Write documentation
    pub const fn new(flags: u32) -> RingBuf {
        RingBuf::with_max_entries(0, flags)
    }

    // TODO: Write documentation
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> RingBuf {
        RingBuf {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_RINGBUF,
                key_size: 0,
                value_size: 0,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            },
        }
    }

    // TODO: Write documentation
    pub const fn pinned(max_entries: u32, flags: u32) -> RingBuf {
        RingBuf {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_RINGBUF,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            },
        }
    }

    // TODO: Write documentation
    pub fn reserve<T>(&mut self, flags: u64) -> Option<&mut T> {
        // SAFETY: We guarantee that `size` is correct by taking `mem::size_of<T>()`.
        // The semantics of bpf_ringbuf_reserve() guarantee that the resulting pointer
        // will be safe to use, provided that it is not null.
        let ptr = unsafe {
            bpf_ringbuf_reserve(
                &mut self.def as *mut _ as *mut _,
                mem::size_of::<T>() as _,
                flags,
            ) as *mut T
        };
        match ptr.is_null() {
            true => None,
            // SAFETY: The semantics of bpf_ringbuf_reserve() guarantee that the resulting
            // pointer will be safe to use, provided that it is not null.
            false => Some(unsafe { &mut *ptr }),
        }
    }

    // TODO: Write documentation
    pub fn discard<T>(&self, data: &mut T, flags: u64) {
        // TODO: Write a SAFETY argument for this
        unsafe { bpf_ringbuf_discard(data as *mut _ as *mut _, flags) };
    }

    // TODO: Write documentation
    pub fn submit<T>(&self, data: &mut T, flags: u64) {
        // TODO: Write a SAFETY argument for this
        unsafe { bpf_ringbuf_submit(data as *mut _ as *mut _, flags) };
    }

    // TODO: Write documentation
    pub fn output<T>(&mut self, data: &T, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_ringbuf_output(
                &mut self.def as *mut _ as *mut _,
                data as *const _ as *mut _,
                mem::size_of::<T>() as _,
                flags,
            )
        };
        if ret < 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }

    // TODO: Write documentation
    pub fn query(&mut self, flags: u64) -> u64 {
        // TODO: Write a SAFETY argument for this
        unsafe { bpf_ringbuf_query(&mut self.def as *mut _ as *mut _, flags) }
    }
}
