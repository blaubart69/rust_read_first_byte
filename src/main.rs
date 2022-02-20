use std::env;
use std::io;
use std::fs::File;
use std::io::{Read};

fn read_one_byte(mut fs: File) -> io::Result<Option<u8>> {
    let mut buf : Vec<u8> = vec![0; 1];

    match fs.read(&mut buf)? {
        0 => Ok( None ),
        _ => Ok( Some(buf[0]) )
    }
}

fn run(filename : &str) -> Result<(), std::io::Error> {
    let fs = File::open(filename )?;
    match read_one_byte(fs)? {
        None           => println!("EOF"),
        Some(byte) => println!("1st byte: {:#02X}", byte)
    }
    Ok(())
}

fn main() {
    let args : Vec<String> = env::args().collect();
    let rc = if args.len() < 2 {
        2
    }
    else {
        match run(args[1].as_str() ) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("io::Error: {}", e);
                e.raw_os_error().unwrap()
            }
        }
    };
    std::process::exit(rc);
}
