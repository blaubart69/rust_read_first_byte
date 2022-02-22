use std::error::Error;
use windows::Win32::Security::{SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::Foundation::{BOOL, HANDLE};

pub fn try_set_privilege() -> std::io::Result<()> {
    let mut tp :TOKEN_PRIVILEGES = TOKEN_PRIVILEGES::default();
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    let mut hToken : HANDLE;
    unsafe {
        if ! OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        &hToken as *mut _).as_bool() {
            Err(std::io::Error::last_os_error())
        }
    }

    Ok(())
}