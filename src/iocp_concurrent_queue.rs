use std::borrow::Borrow;
use std::ffi::c_void;
use std::fmt::Error;
use std::marker::PhantomData;
use std::rc::Rc;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED, PostQueuedCompletionStatus};
use windows::Win32::System::WindowsProgramming::INFINITE;

pub struct IocpConcurrentQueue<T> {
    h_completion_port : HANDLE,
    phantom: PhantomData<T>
}

impl<T> IocpConcurrentQueue<T> {

    pub fn try_dequeue(&self) -> Option<Box<T>> {

        unsafe {
            let mut number_bytes_transferred: u32 = 0;
            let mut overlapped: *mut OVERLAPPED = std::ptr::null_mut();
            let mut item_ptr : usize = 0;

            if !GetQueuedCompletionStatus(
                self.h_completion_port,
                &mut number_bytes_transferred,
                &mut item_ptr as *mut usize,
                &mut overlapped,
                INFINITE).as_bool() {
                None
            } else {
                let item: Box<T> = Box::from_raw(item_ptr as *mut T);
                Some(item)
            }
        }
    }

    pub fn enqueue(&mut self, item : Box<T>) {

        let raw_ptr = Box::into_raw(item);

        if ! unsafe {
            PostQueuedCompletionStatus(
                self.h_completion_port,
                0,
                raw_ptr as usize,
                &OVERLAPPED::default() as *const OVERLAPPED
            ).as_bool() } {
            panic!("E: {} PostQueuedCompletionStatus", std::io::Error::last_os_error().raw_os_error().unwrap() );
        }
    }

    pub fn new(max_threads: u32) -> IocpConcurrentQueue<T> {
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
            h_completion_port : h,
            phantom : PhantomData
        }
    }
}

impl<T> Drop for IocpConcurrentQueue<T> {
    fn drop(&mut self) {
        if ! self.h_completion_port.is_invalid() {
            unsafe { CloseHandle(self.h_completion_port); }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::iocp_concurrent_queue::IocpConcurrentQueue;

    #[test]
    fn one_item() {

        let berni = String::from("butschis");
        let item = Box::new(berni);

        let mut q: IocpConcurrentQueue<String> = IocpConcurrentQueue::new(1);
        q.enqueue(item);
        match q.try_dequeue() {
            None => assert!(false, "do soitat wos aussakumman"),
            Some(i) => assert_eq!("butschis",*i)
        }
    }
    #[test]
    fn two_items() {

        let mut q: IocpConcurrentQueue<String> = IocpConcurrentQueue::new(1);
        q.enqueue(Box::new(String::from("a")));
        q.enqueue(Box::new(String::from("b")));
        match q.try_dequeue() {
            None => assert!(false, "do soitat wos aussakumman"),
            Some(i) => assert_eq!("a",*i)
        }
        match q.try_dequeue() {
            None => assert!(false, "do soitat wos aussakumman"),
            Some(i) => assert_eq!("b",*i)
        }
    }
}