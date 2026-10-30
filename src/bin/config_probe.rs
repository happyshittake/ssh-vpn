#[path = "../config.rs"]
mod config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let destination = std::env::args().nth(1).ok_or(
        std::io::Error::other("Usage: config_probe <destination>"),
    )?;

    let config = config::resolve(&destination)?;

    println!("Host: {}", config.host());
    println!("User: {}", config.user());
    println!("Port: {}", config.port());
    println!("Keys: {:?}", config.host_config.identity_file);

    Ok(())
}