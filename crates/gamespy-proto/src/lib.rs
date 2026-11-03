//! GameSpy packet codecs shared by embedded game servers.
//!
//! No listeners, persistence, title credentials, or platform identity policy.
//! Filter grammar is generic; boolean field classification is supplied by applications.
//! Supported layouts and limits reflect the existing consumers, not every SDK version.

#![allow(clippy::module_name_repetitions)]

pub mod availability;
pub mod browser;
pub mod browser_crypt;
pub mod browser_response;
pub mod gp;
pub mod natneg;
pub mod qr2;

#[cfg(feature = "soap")]
pub mod authservice;
pub mod browser_filter;
#[cfg(feature = "soap")]
pub mod competition;
pub mod http;
pub mod ports;
#[cfg(feature = "soap")]
pub mod sake;
pub mod sake_file;
pub mod title;
