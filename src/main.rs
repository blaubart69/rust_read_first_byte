use std::env;
use std::fs::File;
use std::ffi::c_void;
use std::fmt::Debug;

mod privilege;
mod nt;

fn run (directory_name : &str) -> std::io::Result<()> {
    let directory = nt::open_directory(directory_name)?;
    nt::list_directory(&directory)?;
    Ok(())
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
