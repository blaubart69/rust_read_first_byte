use std::marker::PhantomData;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED, PostQueuedCompletionStatus};
use windows::Win32::System::WindowsProgramming::INFINITE;

fn panic_with_last_error(function_name : &str) -> ! {
    panic!("E: {} {}",
            std::io::Error::last_os_error().raw_os_error().unwrap(),
            function_name);
}

pub struct IocpConcurrentQueue<T> {
    h_completion_port : HANDLE,
    phantom: PhantomData<T>
}

impl<T> IocpConcurrentQueue<T> {

    fn try_dequeue(&self) -> Option<Box<T>> {

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
                panic_with_last_error("GetQueuedCompletionStatus");
            } else {
                if item_ptr == 0 {
                    None
                }
                else {
                    Some(Box::from_raw(item_ptr as *mut T))
                }
            }
        }
    }

    fn post_to_completion_port(&self, val : usize) {
        unsafe {
            if ! PostQueuedCompletionStatus(
                self.h_completion_port,
                0,
                val,
                &OVERLAPPED::default() as *const OVERLAPPED
            ).as_bool() {
                panic_with_last_error("PostQueuedCompletionStatus");
            }
        }
    }

    fn enqueue(&self, item : Box<T>) {
        self.post_to_completion_port( Box::into_raw(item) as usize );
    }

    fn post_end_message(&self) {
        self.post_to_completion_port( 0 );
    }

    fn new(max_threads: u32) -> IocpConcurrentQueue<T> {
        let h = unsafe {
            CreateIoCompletionPort(
                INVALID_HANDLE_VALUE,
                HANDLE::default(),
                0,
                max_threads)
        };

        if h.is_invalid() {
            panic_with_last_error("CreateIoCompletionPort");
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
    use std::ops::Deref;
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
            Some(i) => assert_eq!("a",i.deref())
        }
        match q.try_dequeue() {
            None => assert!(false, "do soitat wos aussakumman"),
            Some(i) => assert_eq!("b",i.deref())
        }
    }
    #[test]
    fn two_items_and_end() {

        let mut q: IocpConcurrentQueue<String> = IocpConcurrentQueue::new(1);
        q.enqueue(Box::new(String::from("a")));
        q.enqueue(Box::new(String::from("b")));
        q.post_end_message();
        match q.try_dequeue() {
            None => assert!(false, "do soitat wos aussakumman"),
            Some(i) => assert_eq!("a",i.deref())
        }
        match q.try_dequeue() {
            None => assert!(false, "do soitat wos aussakumman"),
            Some(i) => assert_eq!("b",i.deref())
        }
        match q.try_dequeue() {
            None => assert!(true),
            Some(i) => assert!(false, "do soitat NIX MEHR aussakumman")
        }
    }
}