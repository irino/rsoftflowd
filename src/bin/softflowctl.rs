use clap::Parser;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

#[derive(Parser, Debug)]
#[command(name = "softflowctl-rs", version = "0.1.0", about = "Control softflowd daemon rewritten in Rust")]
struct Args {
    #[arg(short = 'c', default_value = "/var/run/softflowd.ctl", help = "Specify control socket path")]
    ctlsock: String,

    #[arg(help = "The command to send to softflowd (e.g. statistics, dump-flows, shutdown, expire-all)")]
    command: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut stream = match UnixStream::connect(&args.ctlsock) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("softflowctl: ctl connect(\"{}\") error: {}", args.ctlsock, e);
            std::process::exit(1);
        }
    };

    if let Err(e) = stream.write_all(format!("{}\n", args.command).as_bytes()) {
        eprintln!("softflowctl: write error: {}", e);
        std::process::exit(1);
    }

    let mut response = String::new();
    if let Err(e) = stream.read_to_string(&mut response) {
        eprintln!("softflowctl: read error: {}", e);
        std::process::exit(1);
    }

    print!("{}", response);
    Ok(())
}
