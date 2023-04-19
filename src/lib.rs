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


#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

// use ark_std::{
//     alloc::{ Layout, GlobalAlloc },
//     ffi::c_void,
// };
// #[cfg(not(feature = "std"))]
// #[allow(unused_extern_crates)]
// extern crate alloc;
// // use stdS::ffi::c_void;
// use alloc::alloc::*;

// /// The global allocator type.
// #[derive(Default)]
// #[global_allocator]
// pub struct Allocator;

// unsafe impl GlobalAlloc for Allocator {
//      unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
//         malloc(layout.size() as u32) as *mut u8
//      }
//      unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
//         free(ptr as *mut core::ffi::c_void);
//      }
// }

// /// If there is an out of memory error, just panic.
// #[alloc_error_handler]
// fn my_allocator_error(_layout: Layout) -> ! {
//     panic!("out of memory");
// }

// /// The static global allocator.
// #[global_allocator]
// static GLOBAL_ALLOCATOR: Allocator = Allocator;

// #![forbid(unsafe_code)]
// TODO: forbid unsafe code 
pub mod dkg;
