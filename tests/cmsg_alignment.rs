//! Receiving descriptors must not depend on the allocator handing out
//! well-aligned byte buffers: `cmsghdr` needs 8-byte alignment, and a
//! `Vec<u8>` only guarantees 1. This test binary uses an allocator that
//! deliberately misaligns every byte-aligned allocation (which is allowed),
//! so a control buffer of bytes would trip Rust's misaligned-pointer check.

#![allow(unsafe_code)] // a test allocator

use std::alloc::{GlobalAlloc, Layout, System};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

struct Misaligning;

// SAFETY: forwards to `System`; byte-aligned blocks get one extra byte in
// front, which is undone on deallocation. Alignment 1 is still honoured.
unsafe impl GlobalAlloc for Misaligning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() == 1 {
            let padded = unsafe { Layout::from_size_align_unchecked(layout.size() + 1, 1) };
            let ptr = unsafe { System.alloc(padded) };
            if ptr.is_null() {
                ptr
            } else {
                unsafe { ptr.add(1) }
            }
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.align() == 1 {
            let padded = unsafe { Layout::from_size_align_unchecked(layout.size() + 1, 1) };
            unsafe { System.dealloc(ptr.sub(1), padded) }
        } else {
            unsafe { System.dealloc(ptr, layout) }
        }
    }
}

#[global_allocator]
static ALLOCATOR: Misaligning = Misaligning;

#[test]
fn descriptors_arrive_with_a_misaligning_allocator() {
    let (a, b) = UnixStream::pair().expect("socket pair");
    let (_read, write) = std::io::pipe().expect("pipe");
    rusthorse::protocol::send_frame(&a, &rusthorse::protocol::Request::Status, &[write.as_fd()])
        .expect("send");
    let (_, fds) = rusthorse::protocol::recv_frame(&b).expect("recv");
    assert_eq!(fds.len(), 1);
}
