use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use mqx_auth::DynamicSecurity;
use mqx_broker::{Broker, BrokerError};
use mqx_server::{DynamicSecurityConfig, ServerError};

pub(crate) async fn register(
    broker: &Broker,
    config: Option<&DynamicSecurityConfig>,
    bootstrap: bool,
) -> Result<(), ServerError> {
    let Some(config) = config else { return Ok(()) };
    let path = config.config_file.clone();
    let result = if bootstrap {
        broker
            .register_dynamic_security_with(path.clone(), || {
                load(config).map_err(|source| BrokerError::DynamicSecurityFile { path, source })
            })
            .await
    } else {
        broker.register_dynamic_security(path, None).await
    };
    result.map_err(ServerError::Cluster)
}

// plugins/dynamic-security/config.c: dynsec__config_load;
// config_init.c: dynsec__config_init, get_password_from_init_file.
fn load(config: &DynamicSecurityConfig) -> io::Result<DynamicSecurity> {
    match fs::read(&config.config_file) {
        Ok(bytes) => return DynamicSecurity::parse(&bytes).map_err(io::Error::other),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }

    tracing::info!("Dynamic security plugin config not found, generating a default config.");
    let password = if let Some(path) = &config.password_init_file {
        Some(read_password(path)?)
    } else if let Some(value) = std::env::var_os("MOSQUITTO_DYNSEC_PASSWORD") {
        let password = value.into_encoded_bytes();
        if password.len() < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MOSQUITTO_DYNSEC_PASSWORD must be at least 12 characters",
            ));
        }
        tracing::info!("Using admin password from MOSQUITTO_DYNSEC_PASSWORD environment variable");
        Some(password)
    } else {
        None
    };
    let (state, generated) = DynamicSecurity::initialize(password.as_deref())
        .map_err(|error| io::Error::other(error.to_string()))?;
    if let Some(generated) = generated {
        let mut path = config.config_file.as_os_str().to_os_string();
        path.push(".pw");
        let path = PathBuf::from(path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(generated.as_bytes())?;
        file.sync_all()?;
        tracing::info!("Generated passwords are at {}", path.display());
    }
    Ok(state)
}

fn read_password(path: &Path) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    if std::env::var_os("MOSQUITTO_UNSAFE_ALLOW_SYMLINKS").is_none() {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    tracing::info!("Using admin password from file '{}'", path.display());
    let mut bytes = Vec::new();
    BufReader::new(options.open(path)?.take(1023)).read_until(b'\n', &mut bytes)?;
    if let Some(end) = bytes.iter().position(|&byte| matches!(byte, b'\n' | 0)) {
        bytes.truncate(end);
    }
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'..=b'\r'))
    {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dynamic security password_init_file is empty",
        ));
    }
    Ok(bytes)
}
