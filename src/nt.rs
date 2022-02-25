use std::ffi::c_void;
use std::os::raw::c_ulong;
use std::fmt::Write;
use std::fs::File;


use std::os::windows::io::{FromRawHandle, AsRawHandle};
use std::io::prelude::*;
use std::os::windows::fs::OpenOptionsExt;

use windows::Win32::Foundation::{BOOLEAN, CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, RtlNtStatusToDosError, STATUS_NO_MORE_FILES, STATUS_SUCCESS, UNICODE_STRING};
use windows::Win32::System::WindowsProgramming::{FILE_INFORMATION_CLASS, FileDirectoryInformation, IO_STATUS_BLOCK, PIO_APC_ROUTINE};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};


/*
__kernel_entry NTSYSCALLAPI NTSTATUS NtQueryDirectoryFile(
  [in]           HANDLE                 FileHandle,
  [in, optional] HANDLE                 Event,
  [in, optional] PIO_APC_ROUTINE        ApcRoutine,
  [in, optional] PVOID                  ApcContext,
  [out]          PIO_STATUS_BLOCK       IoStatusBlock,
  [out]          PVOID                  FileInformation,
  [in]           ULONG                  Length,
  [in]           FILE_INFORMATION_CLASS FileInformationClass,
  [in]           BOOLEAN                ReturnSingleEntry,
  [in, optional] PUNICODE_STRING        FileName,
  [in]           BOOLEAN                RestartScan
);
 */
#[allow(non_snake_case)]
#[link(name = "ntdll")]
extern "stdcall" {
    fn NtQueryDirectoryFile(
        FileHandle              : HANDLE,
        Event                   : HANDLE,
        ApcRoutine              : PIO_APC_ROUTINE,
        ApcContext              : *const c_void ,
        IoStatusBlock           : *mut IO_STATUS_BLOCK,
        FileInformation         : *mut c_void,
        Length                  : c_ulong,
        FileInformationClass    : FILE_INFORMATION_CLASS,
        ReturnSingleEntry       : BOOLEAN,
        FileName                : *const UNICODE_STRING,
        RestartScan             : BOOLEAN ) -> NTSTATUS;
}

fn win32_open_file(filename : &str) -> std::io::Result<std::fs::File> {

    use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};

    let h_win32_dir: windows::Win32::Foundation::HANDLE =
        unsafe {
            windows::Win32::Storage::FileSystem::CreateFileW(
                filename,
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                windows::Win32::Foundation::HANDLE::default() )
        };

    if h_win32_dir.is_invalid() {
        Err(std::io::Error::last_os_error())
    }
    else {
        Ok( unsafe { std::fs::File::from_raw_handle(h_win32_dir.0 as *mut c_void ) })
    }
}

pub fn open_directory(name : &str) -> std::io::Result<std::fs::File> {

    std::fs::OpenOptions::new()
        .access_mode( FILE_LIST_DIRECTORY.0 )
        .share_mode( FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0 )
        .attributes( FILE_FLAG_BACKUP_SEMANTICS.0 )
        .open(name)

}

/*
typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;
*/

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct FILE_DIRECTORY_INFORMATION {
    pub NextEntryOffset : c_ulong,
    pub FileIndex : c_ulong,
    pub CreationTime : i64,
    pub LastAccessTime : i64,
    pub LastWriteTime :i64,
    pub ChangeTime : i64,
    pub EndOfFile : u64,
    pub AllocationSize : u64,
    pub FileAttributes : c_ulong,
    pub FileNameLength : c_ulong,
    pub FileName : [u16;1]
}

impl FILE_DIRECTORY_INFORMATION {
    fn filename_as_slice(&self) -> &[u16] {
        unsafe {
            std::slice::from_raw_parts(
                &self.FileName[0] as *const u16,
                (self.FileNameLength / 2) as usize)
        }
    }
}

fn is_dot_or_dotdot(fileattributes : c_ulong, filename : &[u16]) -> bool {

    static WINDOWS_UCS2_DOT : u16 = 0x002E;

    if (fileattributes & FILE_ATTRIBUTE_DIRECTORY.0 ) == 0 { false }
    else if filename[0] != WINDOWS_UCS2_DOT { false }
    else if filename.len() == 1             { true  }
    else if filename[1] != WINDOWS_UCS2_DOT { false }
    else if filename.len() == 2             { true  }
    else                                    { false }

}

fn enumerate_find_buffer<F>(buf : *const u8, buf_len : usize, mut on_entry : F )
where F: FnMut(&FILE_DIRECTORY_INFORMATION, &[u16]) {

    let mut info_ptr = buf as *const FILE_DIRECTORY_INFORMATION;

    loop  {
        let info : &FILE_DIRECTORY_INFORMATION = unsafe { &*info_ptr };

            let filename_slice = info.filename_as_slice();
            if ! is_dot_or_dotdot(info.FileAttributes, filename_slice) {
                on_entry(info, filename_slice);
            }

        if info.NextEntryOffset == 0 {
            break;
        } else {
            info_ptr = unsafe { (info_ptr as *const u8).add( (*info_ptr).NextEntryOffset as usize) as *const FILE_DIRECTORY_INFORMATION };
        }
    }
}

pub fn enumerate_directory<F>(directory : &std::fs::File, buf: &mut Vec<u8>, mut on_entry : F ) -> std::io::Result<()>
    where F: FnMut(&FILE_DIRECTORY_INFORMATION, &[u16]) {

    let mut io_status_block : IO_STATUS_BLOCK = IO_STATUS_BLOCK::default();

    loop {
        let win_handle  =
            windows::Win32::Foundation::HANDLE(directory.as_raw_handle() as isize);

        let status: NTSTATUS = unsafe {
            NtQueryDirectoryFile(
                win_handle
                , HANDLE::default()  // event
                , PIO_APC_ROUTINE::default() // APC routine
                , std::ptr::null()      // APC context
                , &mut io_status_block
                , std::mem::transmute(&(buf[0]) )
                , buf.len() as c_ulong
                , FileDirectoryInformation
                , BOOLEAN(0)      // ReturnSingleEntry
                , std::ptr::null()    // Filename
                , BOOLEAN(0)) // RestartScan
        };

        if status == STATUS_NO_MORE_FILES {
            break Ok(())
        }
        else if status != STATUS_SUCCESS {
            //break Err( unsafe { RtlNtStatusToDosError(status) } )
            break Err(std::io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32 ));
        }
        else if io_status_block.Information == 0 {
            break Err(std::io::Error::from_raw_os_error(ERROR_INSUFFICIENT_BUFFER.0 as i32));
        }
        else {
            enumerate_find_buffer(&(buf[0]), io_status_block.Information, &mut on_entry);
        }
    }
}
