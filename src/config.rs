use std::io;

pub fn resolve(destination: &str) -> Result<russh_config::Config, Box<dyn std::error::Error>> {
    let (user, address) = match destination.split_once('@') {
        Some((user, address)) if !user.is_empty() => (Some(user), address),
        Some(_) => return Err(invalid("SSH user cannot be empty").into()),
        None => (None, destination),
    };

    // shortcut: IPv4/hostname only, add bracketed IPv6 parsing when needed.
    let (host, port) = match address.split_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse()?;
            if port == 0 {
                return Err(invalid("SSH port must be 1..65535").into());
            }
            (host, Some(port))
        }
        None => (address, None),
    };

    if host.is_empty() || host.contains('@') {
        return Err(invalid("Invalid SSH destination").into());
    }

    let path = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| invalid("HOME is missing"))?
        .join(".ssh/config");

    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };

    // Jangan diam-diam mengabaikan directive yang belum didukung.
    for line in contents.lines() {
        let directive = line.split_whitespace().next().unwrap_or("");
        if directive.eq_ignore_ascii_case("include") || directive.eq_ignore_ascii_case("match") {
            return Err(invalid("Include/Match are not supported yet").into());
        }
    }
    let contents = format!("Host *\n{contents}");
    let mut config = russh_config::parse(&contents, host)?;

    if config.host_config.proxy_jump.is_some() || config.host_config.proxy_command.is_some() {
        return Err(invalid("ProxyJump/ProxyCommand are not supported yet").into());
    }

    if let Some(user) = user {
        config.user = Some(user.to_owned());
    }

    // Override field ini karena Config::port() mendahulukan host_config.port.
    if let Some(port) = port {
        config.host_config.port = Some(port);
    }

    Ok(config)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_user_and_port() {
        // Parsing config kosong supaya tes tidak bergantung pada ~/.ssh/config.
        let mut config = russh_config::parse("", "192.0.2.1").unwrap();
        config.user = Some("ndjoe".into());
        config.host_config.port = Some(2222);

        assert_eq!(config.host(), "192.0.2.1");
        assert_eq!(config.user(), "ndjoe");
        assert_eq!(config.port(), 2222);
    }
}
