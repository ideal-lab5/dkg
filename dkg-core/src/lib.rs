#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
// #![deny(unsafe_code)]
#![doc = include_str!("../README.md")]

// #![forbid(unsafe_code)]
// TODO: forbid unsafe code 
pub mod dkg;

pub mod types;

// #[cfg(feature = "std")]
pub mod ser;
