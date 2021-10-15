//! A logging framework for eBPF programs.
//!
//! This is the user space side of the [Aya] logging framework. For the eBPF
//! side, see the `aya-log-ebpf` crate.
//!
//! `aya-log` provides the [BpfLogger] type, which reads log records created by
//! `aya-log-ebpf` and logs them using the [log] crate. Any logger that
//! implements the [Log] trait can be used with this crate.
//!
//! # Example:
//!
//! This example uses the [simplelog] crate to log messages to the terminal.
//!
//! ```no_run
//! # let mut bpf = aya::Bpf::load(&[], None)?;
//! use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
//! use aya_log::BpfLogger;
//!
//! // initialize simplelog::TermLogger as the default logger
//! TermLogger::init(
//!     LevelFilter::Debug,
//!     ConfigBuilder::new()
//!         .set_target_level(LevelFilter::Error)
//!         .set_location_level(LevelFilter::Error)
//!         .build(),
//!     TerminalMode::Mixed,
//!     ColorChoice::Auto,
//! )
//! .unwrap();
//!
//! // start reading aya-log records and log them using the default logger
//! BpfLogger::init(&mut bpf).unwrap();
//! ```
//!
//! With the following eBPF code:
//!
//! ```no_run
//! # let ctx = ();
//! use aya_log_ebpf::{debug, error, info, trace, warn};
//!
//! error!(&ctx, "this is an error message 🚨");
//! warn!(&ctx, "this is a warning message ⚠️");
//! info!(&ctx, "this is an info message ℹ️");
//! debug!(&ctx, "this is a debug message ️🐝");
//! trace!(&ctx, "this is a trace message 🔍");
//! ```
//! Outputs:
//!
//! ```text
//! 21:58:55 [ERROR] xxx: [src/main.rs:35] this is an error message 🚨
//! 21:58:55 [WARN] xxx: [src/main.rs:36] this is a warning message ⚠️
//! 21:58:55 [INFO] xxx: [src/main.rs:37] this is an info message ℹ️
//! 21:58:55 [DEBUG] (7) xxx: [src/main.rs:38] this is a debug message ️🐝
//! 21:58:55 [TRACE] (7) xxx: [src/main.rs:39] this is a trace message 🔍
//! ```
//!
//! [Aya]: https://docs.rs/aya
//! [simplelog]: https://docs.rs/simplelog
//! [Log]: https://docs.rs/log/0.4.14/log/trait.Log.html
//! [log]: https://docs.rs/log
//!
use std::{convert::TryInto, io, mem, ptr, sync::Arc};

use aya_log_common::{RecordField, LOG_BUF_CAPACITY, LOG_FIELDS};
use bytes::BytesMut;
use log::{logger, Level, Log, Record};
use thiserror::Error;

use aya::{
    maps::{
        perf::{AsyncPerfEventArray, PerfBufferError},
        MapError,
    },
    util::online_cpus,
    Bpf, Pod,
};

/// Log messages generated by `aya_log_ebpf` using the [log] crate.
///
/// For more details see the [module level documentation](crate).
pub struct BpfLogger;

impl BpfLogger {
    /// Starts reading log records created with `aya-log-ebpf` and logs them
    /// with the default logger. See [log::logger].
    pub fn init(bpf: &mut Bpf) -> Result<BpfLogger, Error> {
        BpfLogger::init_with_logger(bpf, DefaultLogger {})
    }

    /// Starts reading log records created with `aya-log-ebpf` and logs them
    /// with the given logger.
    pub fn init_with_logger<T: Log + 'static>(
        bpf: &mut Bpf,
        logger: T,
    ) -> Result<BpfLogger, Error> {
        let logger = Arc::new(logger);
        let mut logs: AsyncPerfEventArray<_> = bpf.map_mut("AYA_LOGS")?.try_into()?;

        for cpu_id in online_cpus().map_err(Error::InvalidOnlineCpu)? {
            let mut buf = logs.open(cpu_id, None)?;

            let log = logger.clone();
            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(LOG_BUF_CAPACITY))
                    .collect::<Vec<_>>();

                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();

                    #[allow(clippy::needless_range_loop)]
                    for i in 0..events.read {
                        let buf = &mut buffers[i];
                        log_buf(buf, &*log).unwrap();
                    }
                }
            });
        }

        Ok(BpfLogger {})
    }
}

#[derive(Copy, Clone, Debug)]
struct DefaultLogger;

impl Log for DefaultLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        log::logger().enabled(metadata)
    }

    fn log(&self, record: &Record) {
        log::logger().log(record)
    }

    fn flush(&self) {
        log::logger().flush()
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("error opening log event array")]
    MapError(#[from] MapError),

    #[error("error opening log buffer")]
    PerfBufferError(#[from] PerfBufferError),

    #[error("invalid /sys/devices/system/cpu/online format")]
    InvalidOnlineCpu(#[source] io::Error),
}

fn log_buf(mut buf: &[u8], logger: &dyn Log) -> Result<(), ()> {
    let mut target = None;
    let mut level = Level::Trace;
    let mut module = None;
    let mut file = None;
    let mut line = None;
    let mut log = None;

    for _ in 0..LOG_FIELDS {
        let (attr, rest) = unsafe { TagLenValue::<'_, RecordField>::try_read(buf)? };

        match attr.tag {
            RecordField::Target => {
                target = Some(std::str::from_utf8(attr.value).map_err(|_| ())?);
            }
            RecordField::Level => {
                level = unsafe { ptr::read_unaligned(attr.value.as_ptr() as *const _) }
            }
            RecordField::Module => {
                module = Some(std::str::from_utf8(attr.value).map_err(|_| ())?);
            }
            RecordField::File => {
                file = Some(std::str::from_utf8(attr.value).map_err(|_| ())?);
            }
            RecordField::Line => {
                line = Some(u32::from_ne_bytes(attr.value.try_into().map_err(|_| ())?));
            }
            RecordField::Log => {
                log = Some(std::str::from_utf8(attr.value).map_err(|_| ())?);
            }
        }

        buf = rest;
    }

    logger.log(
        &Record::builder()
            .args(format_args!("{}", log.ok_or(())?))
            .target(target.ok_or(())?)
            .level(level)
            .module_path(module)
            .file(file)
            .line(line)
            .build(),
    );
    logger.flush();
    Ok(())
}

struct TagLenValue<'a, T: Pod> {
    tag: T,
    value: &'a [u8],
}

impl<'a, T: Pod> TagLenValue<'a, T> {
    unsafe fn try_read(mut buf: &'a [u8]) -> Result<(TagLenValue<'a, T>, &'a [u8]), ()> {
        if buf.len() < mem::size_of::<T>() + mem::size_of::<usize>() {
            return Err(());
        }

        let tag = ptr::read_unaligned(buf.as_ptr() as *const T);
        buf = &buf[mem::size_of::<T>()..];

        let len = usize::from_ne_bytes(buf[..mem::size_of::<usize>()].try_into().unwrap());
        buf = &buf[mem::size_of::<usize>()..];

        if buf.len() < len {
            return Err(());
        }

        Ok((
            TagLenValue {
                tag,
                value: &buf[..len],
            },
            &buf[len..],
        ))
    }
}
