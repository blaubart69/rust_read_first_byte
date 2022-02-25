use std::env;
use std::fs::File;
use std::fmt::Debug;

mod privilege;
mod nt;

use nt::FILE_DIRECTORY_INFORMATION;

fn print_file_entry(find_data : &FILE_DIRECTORY_INFORMATION, filename : &[u16] ) {
    let filename_w = widestring::U16Str::from_slice(filename);

    println!("{:>12}\t{}", find_data.EndOfFile, filename_w.display());

}

fn run (directory_name : &str) -> std::io::Result<()> {
    let directory = nt::open_directory(directory_name)?;
    let mut buf: Vec<u8> = vec![0u8;64*1024];
    nt::enumerate_directory(
        &directory,
        &mut buf,
        | find_data : &nt::FILE_DIRECTORY_INFORMATION, filename : &[u16] | {
            print_file_entry(find_data, filename);
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
