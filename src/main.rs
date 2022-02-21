use std::env;
use std::ffi::c_void;
use std::os::raw::{c_ulong};
use windows::Win32::Foundation::{BOOL, BOOLEAN, CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, NTSTATUS, RtlNtStatusToDosError, STATUS_NO_MORE_FILES, STATUS_SUCCESS, UNICODE_STRING};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows::Win32::System::WindowsProgramming::{FILE_INFORMATION_CLASS, FileDirectoryInformation, IO_STATUS_BLOCK, PIO_APC_ROUTINE};
/*
fn read_one_byte(mut fs: &File) -> io::Result<Option<u8>> {
    let mut buf : Vec<u8> = vec![0; 1];

    match fs.read(&mut buf)? {
        0 => Ok( None ),
        _ => Ok( Some(buf[0]) )
    }
}

fn run(filename : &str) -> Result<(), std::io::Error> {
    let fs = File::open(filename )?;

    match read_one_byte(&fs)? {
        None           => println!("EOF"),
        Some(byte) => println!("1st byte: {:#02X}", byte)
    }
    Ok(())
}
*/
struct SafeWin32Handle {
    handle : HANDLE
}

impl Drop for SafeWin32Handle {
    fn drop(&mut self) {
        if ! self.handle.is_invalid() {
            let rc : BOOL;
            unsafe { rc = CloseHandle(self.handle); }
            if rc.as_bool() {
                println!("handle closed");
            }
            else {
                eprintln!("{} CloseHandle", std::io::Error::last_os_error());
            }
        }
    }
}

impl SafeWin32Handle {
    fn new(handle : HANDLE) -> SafeWin32Handle {
        SafeWin32Handle { handle }
    }
}

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

fn win32_open_file(filename : &str) -> std::io::Result<SafeWin32Handle> {

    let handle : HANDLE =
        unsafe {
            windows::Win32::Storage::FileSystem::CreateFileW(
                filename,
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                HANDLE::default() )
        };

    if handle.is_invalid() {
        Err(std::io::Error::last_os_error())
    }
    else {
        Ok(SafeWin32Handle::new(handle))
    }
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
struct FILE_DIRECTORY_INFORMATION {
    NextEntryOffset : c_ulong,
    FileIndex : c_ulong,
    CreationTime : i64,
    LastAccessTime : i64,
    LastWriteTime :i64,
    ChangeTime : i64,
    EndOfFile : u64,
    AllocationSize : u64,
    FileAttributes : c_ulong,
    FileNameLength : c_ulong,
    FileName : [u16;1]
}

impl FILE_DIRECTORY_INFORMATION {
    fn filename_wide(&self) -> &widestring::U16Str {
        unsafe {
            widestring::U16Str::from_ptr(
                &(self.FileName[0]),
                (self.FileNameLength as usize) / 2 ) }
    }
}

fn print_find_buffer(buf : *const u8, buf_len : usize ) {

    eprintln!("buf_len: {}", buf_len);

    let mut info_ptr = buf as *const FILE_DIRECTORY_INFORMATION;

    loop  {
        let info : &FILE_DIRECTORY_INFORMATION = unsafe { &*info_ptr };
        let name = info.filename_wide();

        println!("[{}]", name.display());

        if info.NextEntryOffset == 0 {
            break;
        } else {
            info_ptr = unsafe { (info_ptr as *const u8).add( (*info_ptr).NextEntryOffset as usize) as *const FILE_DIRECTORY_INFORMATION };
        }
    }
}

fn list_directory(directoryname : &str) -> std::io::Result<()> {

    let directory_handle = win32_open_file(directoryname)?;

    let mut io_status_block : IO_STATUS_BLOCK = IO_STATUS_BLOCK::default();
    const BUFFERSIZE : usize = 64*1024;
    let buf: Vec<u8> = vec![0u8;BUFFERSIZE];

    loop {
        let status: NTSTATUS = unsafe {
            NtQueryDirectoryFile(
                directory_handle.handle
                , HANDLE::default()  // event
                , PIO_APC_ROUTINE::default() // APC routine
                , std::ptr::null()      // APC context
                , &mut io_status_block
                , std::mem::transmute(&(buf[0]) )
                , BUFFERSIZE as c_ulong
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
            break Err(std::io::Error::from_raw_os_error((unsafe { RtlNtStatusToDosError(status) } as i32) ));
        }
        else if io_status_block.Information == 0 {
            break Err(std::io::Error::from_raw_os_error(ERROR_INSUFFICIENT_BUFFER.0 as i32));
        }
        else {
            print_find_buffer(&(buf[0]), io_status_block.Information);
        }
    }
}

fn main() {
    let args : Vec<String> = env::args().collect();
    let rc = if args.len() < 2 {
        2
    }
    else {
        let directory_name = args[1].as_str();
        match list_directory(directory_name) {
            Err(e) => {
                eprintln!("{} [{}]", e, directory_name);
                e.raw_os_error().unwrap()
            },
            Ok(_) => {
                0
            }
        }
    };
    std::process::exit(rc);
}
