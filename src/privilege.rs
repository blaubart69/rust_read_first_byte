use windows::Win32::Security::{AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::Foundation::{BOOL, CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, PWSTR};
use windows::Win32::System::SystemServices::SE_BACKUP_NAME;

pub fn try_enable_backup_privilege() -> std::io::Result<()> {

    let mut tp :TOKEN_PRIVILEGES = TOKEN_PRIVILEGES::default();
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    let mut h_token = HANDLE::default();

    let rc = unsafe {
        if ! OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut h_token).as_bool() {
                Err(std::io::Error::last_os_error())
        }
        else if ! LookupPrivilegeValueW(
            PWSTR::default(),
            SE_BACKUP_NAME,
            &mut (tp.Privileges[0].Luid) as *mut _ ).as_bool() {
            Err(std::io::Error::last_os_error())
        }
        else if  ! AdjustTokenPrivileges(
            h_token,
            BOOL::from(false),
            &tp as *const _,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            core::ptr::null_mut(),
            core::ptr::null_mut()).as_bool() {
            Err(std::io::Error::last_os_error())
        }
        else if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
            Err( std::io::Error::last_os_error() )
        }
        else {
            Ok(())
        }
    };

    if ! h_token.is_invalid() {
        unsafe { CloseHandle(h_token); }
    }

    rc

}