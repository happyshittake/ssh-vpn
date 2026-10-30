use std::io;
use tokio::process::Command;

pub async fn add(interface: &str, target: &str) -> io::Result<()> {
    change("add", interface, target).await
}

pub async fn remove(interface: &str, target: &str) -> io::Result<()> {
    change("delete", interface, target).await
}

async fn change(
    action: &str,
    interface: &str,
    target: &str,
) -> io::Result<()> {
    let output = Command::new("/sbin/route")
        .args([
            "-n", action,
            "-net", target,
            "-interface", interface,
        ])
        .output()
        .await?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "route {action} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        )));
    }

    Ok(())
}