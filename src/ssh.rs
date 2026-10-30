use std::{io, net::SocketAddr, path::{Path, PathBuf}, sync::Arc};

use russh::{
    client,
    keys::{
        PrivateKeyWithHashAlg, PublicKeyOrCertificate, check_known_hosts_path, load_secret_key,
    },
};

use std::time::Duration;

struct HostVerifier {
    host: String,
    port: u16,
    known_hosts: PathBuf,
}

impl client::Handler for HostVerifier {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return Ok(false);
        };

        Ok(check_known_hosts_path(
            &self.host,
            self.port,
            &key,
            &self.known_hosts,
        )?)
    }
}

pub struct Ssh {
    session: client::Handle<HostVerifier>,
}

impl Ssh {
    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        key_path: &Path,
        known_host: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let key = load_secret_key(key_path, None)?;

        let verifier = HostVerifier {
            host: host.to_owned(),
            port,
            known_hosts: known_host.into(),
        };

        let config = client::Config {
            keepalive_interval: Some(Duration::from_secs(10)),
            keepalive_max: 3,
            ..Default::default()
        };

        let mut session =
            client::connect(Arc::new(config), (host, port), verifier).await?;

        let rsa_hash = session.best_supported_rsa_hash().await?.flatten();

        let auth = session
            .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash))
            .await?;

        if !auth.success() {
            return Err(io::Error::other("SSH authentication failed").into());
        }

        Ok(Self { session })
    }

    pub async fn open_tcp(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Result<russh::Channel<client::Msg>, russh::Error> {
        self.session
            .channel_open_direct_tcpip(
                destination.ip().to_string(),
                u32::from(destination.port()),
                source.ip().to_string(),
                u32::from(source.port()),
            )
            .await
    }

    pub async fn wait_closed(&self) {
       while !self.session.is_closed() {
           tokio::time::sleep(Duration::from_secs(1)).await;
       }
   }
}
