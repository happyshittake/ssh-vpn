mod config;
mod route;
mod ssh;

use std::{net::Ipv4Addr, path::PathBuf, sync::Arc};

use clap::Parser;
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use tokio::io::{self, copy_bidirectional};
use tun::AbstractDevice;

#[derive(Parser)]
#[command(version, about = "Route TCP traffic through SSH")]
struct Cli {
    /// SSH alias or user@IPv4:port
    destination: String,

    /// IPv4 network to tunnel, e.g. 1.1.1.1/32
    #[arg(value_name = "CIDR")]
    target: String,

    /// Override IdentityFile from SSH config
    #[arg(long)]
    key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let (address, prefix) = cli.target.split_once('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Target must use CIDR, e.g. 1.1.1.1/32",
        )
    })?;

    let address: Ipv4Addr = address.parse()?;
    let prefix: u32 = prefix.parse()?;

    if !(1..=32).contains(&prefix) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Prefix must be 1..32; default route is not supported yet",
        )
        .into());
    }

    let mask = u32::MAX << (32 - prefix);
    let network = u32::from(address) & mask;

    if network != u32::from(address) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Use the network address, e.g. 10.20.0.0/16",
        )
        .into());
    }

    let resolved = config::resolve(&cli.destination)?;

    let ssh_host: Ipv4Addr = resolved.host().parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SSH host must be an IPv4 address",
        )
    })?;

    for protected in [
        ssh_host,
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(198, 18, 0, 1),
        Ipv4Addr::new(198, 18, 0, 2),
    ] {
        if u32::from(protected) & mask == network {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Target includes protected address {protected}"),
            )
            .into());
        }
    }

    let target = format!("{address}/{prefix}");

    let key = match cli.key {
        Some(key) => key,
        None => match resolved.host_config.identity_file.as_deref() {
            Some([key]) => key.clone(),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Specify --key when config has zero or multiple IdentityFile entries",
                )
                .into());
            }
        },
    };

    let known_hosts = match &resolved.host_config.user_known_hosts_file {
        Some(path) => path.clone(),
        None => PathBuf::from(
            std::env::var_os("HOME").ok_or_else(|| io::Error::other("HOME is missing"))?,
        )
        .join(".ssh/known_hosts"),
    };

    let user = resolved.user();

    let ssh = Arc::new(
        ssh::Ssh::connect(
            resolved.host(),
            resolved.port(),
            &user,
            &key,
            &known_hosts,
        )
        .await?,
    );

    println!("SSH connected");

    let mut config = tun::Configuration::default();
    config
        .address((198, 18, 0, 1))
        .destination((198, 18, 0, 2))
        .netmask((255, 255, 255, 255))
        .mtu(1500)
        .up();

    config.platform_config(|c| {
        c.enable_routing(false);
    });

    let device = tun::create_as_async(&config)?;
    let interface = device.tun_name()?;
    println!("Interface: {}", interface);

    let (stack, runner, _, listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(false)
        .enable_icmp(false)
        .mtu(1500)
        .build()?;

    let runner = runner.ok_or_else(|| io::Error::other("TCP runner missing"))?;
    let mut listener = listener.ok_or_else(|| io::Error::other("TCP listener missing"))?;

    let (mut tun_tx, mut tun_rx) = device.into_framed().split();
    let (mut stack_tx, mut stack_rx) = stack.split();

    // Paket keluar dari OS masuk ke TCP/IP stack.
    let tun_to_stack = async move {
        while let Some(packet) = tun_rx.next().await {
            stack_tx.send(packet?).await?;
        }
        Err::<(), io::Error>(io::Error::other("TUN closed"))
    };

    let stack_to_tun = async move {
        while let Some(packet) = stack_rx.next().await {
            tun_tx.send(packet?).await?;
        }
        Err::<(), io::Error>(io::Error::other("Stack closed"))
    };

    let connection_ssh = Arc::clone(&ssh);

    let connections = async move {
        while let Some((mut stream, source, destination)) = listener.next().await {
            let ssh = Arc::clone(&connection_ssh);

            tokio::spawn(async move {
                let result = async {
                    let channel = ssh.open_tcp(source, destination).await?;
                    let mut upstream = channel.into_stream();

                    copy_bidirectional(&mut stream, &mut upstream).await?;

                    Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                }
                .await;

                if let Err(error) = result {
                    eprintln!("TCP {source} -> {destination}: {error}");
                }
            });
        }

        Err::<(), io::Error>(io::Error::other("TCP listener closed"))
    };

    route::add(&interface, &target).await?;
    println!("Route {target} -> {interface} installed");

    let tunnel = async {
        tokio::try_join!(runner, tun_to_stack, stack_to_tun, connections)?;

        Ok::<(), io::Error>(())
    };

    tokio::pin!(tunnel);

    let result = tokio::select! {
        result = &mut tunnel => result,

        signal = tokio::signal::ctrl_c() => {
            signal.map(|()| {
                println!("Stopping tunnel...");
            })
        }

        _ = ssh.wait_closed() => {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "SSH disconnected",
            ))
        }
    };

    let cleanup = route::remove(&interface, &target).await;

    if let Err(error) = &cleanup {
        eprintln!("Route cleanup failed: {error}");
    } else {
        println!("Route removed");
    }

    result?;
    cleanup?;
    Ok(())
}
