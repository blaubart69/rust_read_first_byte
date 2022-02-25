use std::borrow::Borrow;
use std::ffi::c_void;
use std::fmt::Error;
use std::rc::Rc;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED, PostQueuedCompletionStatus};
use windows::Win32::System::WindowsProgramming::INFINITE;

pub struct IocpConcurrentQueue {
    h_completion_port : HANDLE,
}

impl<T> IocpConcurrentQueue {

    pub fn try_dequeue(&self) -> Option<Box<T>> {

        let mut item_ptr : c_void;

        if unsafe {
            let mut number_bytes_transferred : u32;
            let mut overlapped : *mut OVERLAPPED;

            GetQueuedCompletionStatus(
                self.h_completion_port,
                &mut number_bytes_transferred,
                &item_ptr as *mut _ as *mut usize,
                &mut overlapped,
                INFINITE).as_bool()
        } {
            let item : Box<T> = Box
            Some(item)
        }
        else {
            None
        }


    }

    pub fn enqueue(&mut self, item : T) {

        let rc = Rc::new(item);

        if ! unsafe {
            PostQueuedCompletionStatus(
                self.h_completion_port,
                0,
                &item as *const _ as usize,
                &OVERLAPPED::default() as *const OVERLAPPED
            ).as_bool() } {
            panic!("E: {} PostQueuedCompletionStatus", std::io::Error::last_os_error().raw_os_error().unwrap() );
        }
    }

    pub fn new(max_threads: u32) -> IocpConcurrentQueue {
        let h = unsafe {
            CreateIoCompletionPort(
                INVALID_HANDLE_VALUE,
                HANDLE::default(),
                0,
                max_threads)
        };

        if h.is_invalid() {
            panic!("E: {} CreateIoCompletionPort", std::io::Error::last_os_error().raw_os_error().unwrap() );
        }

        IocpConcurrentQueue {
            h_completion_port : h
        }
    }
}

impl Drop for IocpConcurrentQueue {
    fn drop(&mut self) {
        if ! self.h_completion_port.is_invalid() {
            unsafe { CloseHandle(self.h_completion_port); }
        }
    }
}