use std::env;
use std::fs::File;
use std::io::Write;
use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM};
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

mod privilege;
mod nt;
mod iocp_concurrent_queue;

use nt::FILE_DIRECTORY_INFORMATION;

fn convert_filetime_to_localtime(filetime : &FILETIME) -> Option<SYSTEMTIME> {
    unsafe {
        let mut sys_time = SYSTEMTIME::default();
        let mut localtime = SYSTEMTIME::default();

        if ! FileTimeToSystemTime(filetime, &mut sys_time).as_bool() {
            None
        }
        else if ! SystemTimeToTzSpecificLocalTime(std::ptr::null(), &sys_time, &mut localtime).as_bool() {
            None
        }
        else {
            Some(localtime)
        }
    }
}

fn print_file_entry(find_data : &FILE_DIRECTORY_INFORMATION, filename : &[u16], print_buf : &mut Vec<u8> ) {

    print_buf.clear();

    match convert_filetime_to_localtime(&find_data.LastWriteTime) {
        None => write!(print_buf, "{:#016X}", (find_data.LastWriteTime.dwHighDateTime as u64) << 32 | find_data.LastWriteTime.dwLowDateTime as u64),
        Some(localtime) => write!(print_buf, "{:#4}-{:#02}-{:#02} {:#02}:{:#02}:{:#02}", localtime.wYear, localtime.wMonth, localtime.wDay, localtime.wHour, localtime.wMinute, localtime.wSecond)
    };

    let filename_w = widestring::U16Str::from_slice(filename);
    write!(print_buf, "\t{}{}{}{}{}{}{}{}{}\t{:>12}\t{}\n",
             if ( find_data.FileAttributes  &  FILE_ATTRIBUTE_ARCHIVE.0             ) != 0 { 'A' } else { '-' },
             if ( find_data.FileAttributes  &  FILE_ATTRIBUTE_SYSTEM.0              ) != 0 { 'S' } else { '-' },
             if ( find_data.FileAttributes  &  FILE_ATTRIBUTE_HIDDEN.0              ) != 0 { 'H' } else { '-' },
             if ( find_data.FileAttributes  &  FILE_ATTRIBUTE_READONLY.0            ) != 0 { 'R' } else { '-' },
             if ( find_data.FileAttributes  &  FILE_ATTRIBUTE_DIRECTORY.0           ) != 0 { 'D' } else { '-' },
             if ( find_data.FileAttributes  &  FILE_ATTRIBUTE_ENCRYPTED.0           ) != 0 { 'E' } else { '-' },
             if ( find_data.FileAttributes  &  FILE_ATTRIBUTE_COMPRESSED.0          ) != 0 { 'C' } else { '-' },
             if ( find_data.FileAttributes  &  FILE_ATTRIBUTE_OFFLINE.0             ) != 0 { 'O' } else { '-' },
             if ( find_data.FileAttributes  &  FILE_ATTRIBUTE_NOT_CONTENT_INDEXED.0 ) != 0 { 'I' } else { '-' },
             find_data.EndOfFile,
             filename_w.display());

    std::io::stdout().write(&print_buf).unwrap();
}

fn run (directory_name : &str) -> std::io::Result<()> {
    let directory = nt::open_directory(directory_name)?;
    let mut buf: Vec<u8> = vec![0u8;64*1024];

    let mut print_buffer :Vec<u8> = vec![0;128];

    nt::enumerate_directory(
        &directory,
        &mut buf,
        | find_data : &nt::FILE_DIRECTORY_INFORMATION, filename : &[u16] | {
            print_file_entry(find_data, filename, &mut print_buffer);
        } )
}

fn main() {

    let args : Vec<String> = env::args().collect();
    let rc = if args.len() < 2 {
        2
    }
    else {
        match privilege::try_enable_backup_privilege() {
            Err(e) => println!("{}", e),
            _ => ()
        }

        match run(args[1].as_str()) {
            Err(e) => {
                eprintln!("{} [{}]", e, args[1].as_str());
                e.raw_os_error().unwrap()
            },
            Ok(_) => {
                0
            }
        }
    };
    std::process::exit(rc);
}
