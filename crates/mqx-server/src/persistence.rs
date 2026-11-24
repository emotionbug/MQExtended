use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};

use mqx_broker::{Broker, PersistenceCounts, PersistentState};
use mqx_server::{ListenerProtocol, PersistenceConfig, ServerConfig, ServerError};
use tokio::{
    sync::{Mutex, watch},
    time::{self, Instant},
};

// src/database.c: db__open fails when persist__restore does, and
// src/mosquitto.c: main then exits with status 1.
pub(super) const RESTORE_FAILED: &str = "Unable to restore persistent database";
pub(super) const IMPORT_FAILED: &str = "Unable to import Mosquitto persistence database";

const AUTOSAVE_RETRY_DELAY: Duration = Duration::from_secs(1);

pub(super) struct Persistence {
    config: watch::Sender<PersistenceConfig>,
    // Serialize backups and remember a native path we couldn't safely clear.
    writer: Mutex<Option<PathBuf>>,
}

impl Persistence {
    pub(super) fn new(config: PersistenceConfig) -> Self {
        Self {
            config: watch::Sender::new(config),
            writer: Mutex::new(None),
        }
    }

    pub(super) fn reload(&self, config: PersistenceConfig) {
        self.config.send_replace(config);
    }

    pub(super) async fn restore(
        &self,
        broker: &Broker,
        config: &ServerConfig,
    ) -> Result<(), ServerError> {
        if !config.persistence.enabled {
            return Ok(());
        }
        let native = snapshot_path(&config.persistence);
        let image = match load_database(
            RESTORE_FAILED,
            native.clone(),
            config.auto_recover,
            PersistentState::read_snapshot,
        )
        .await?
        {
            Load::Restored(image) => {
                let counts = image.counts();
                broker
                    .restore_persistence(image)
                    .await
                    .map_err(ServerError::Cluster)?;
                log_restored(counts);
                return Ok(());
            }
            Load::Missing => {
                // A crash after discard but before the next save must not
                // revive data consumed since the original import.
                let discarded = discarded_path(&native);
                if file_job(RESTORE_FAILED, discarded.clone(), move || {
                    Ok(database_metadata(&discarded)?.is_some())
                })
                .await?
                {
                    return Ok(());
                }
                read_mosquitto(config, config.auto_recover).await?
            }
            Load::Discarded => return Ok(()),
            Load::Unusable => {
                tracing::warn!(
                    "Persistence writes disabled for '{}' until it can be safely recovered",
                    native.display()
                );
                *self.writer.lock().await = Some(native);
                return Ok(());
            }
        };
        if let Load::Restored(image) = image {
            let counts = image.counts();
            broker
                .restore_persistence(image)
                .await
                .map_err(ServerError::Cluster)?;
            // Make migration durable before serving. A later crash cannot
            // revive messages already consumed from the original Mosquitto DB.
            let (_, state) = broker
                .persistence_snapshot(false)
                .expect("standalone broker");
            write_snapshot(native, state).await?;
            log_imported(&config.persistence.mosquitto_path(), counts);
        }
        Ok(())
    }

    pub(super) async fn backup(
        &self,
        broker: &Broker,
        shutdown: bool,
    ) -> Result<Option<u64>, ServerError> {
        let mut writer = self.writer.lock().await;
        let path = {
            let config = self.config.borrow();
            if !config.enabled {
                return Ok(None);
            }
            snapshot_path(&config)
        };
        if let Some(blocked) = writer.as_ref() {
            // Check the original path, even if reload selects an alias.
            let blocked = blocked.clone();
            let destination = path.clone();
            let cleared = file_job(RESTORE_FAILED, blocked.clone(), move || {
                let recovered = match read_for_recovery(&blocked, PersistentState::read_snapshot) {
                    // A valid replacement belongs to the operator. We never
                    // loaded it and cannot safely overwrite it with live state.
                    Ok(image) => image.is_none(),
                    Err(error) if is_corruption(&error) => discard_database(&blocked).is_ok(),
                    Err(error) => return Err(error),
                };
                Ok(
                    recovered
                        && (destination == blocked || database_metadata(&destination).is_ok()),
                )
            })
            .await
            .inspect_err(|error| tracing::error!("{error}"))?;
            if !cleared {
                return Ok(None);
            }
            *writer = None;
        }
        let Some((changes, state)) = broker.persistence_snapshot(shutdown) else {
            return Ok(None);
        };
        write_snapshot(path, state)
            .await
            .inspect_err(|error| tracing::error!("{error}"))?;
        Ok(Some(changes))
    }

    pub(super) async fn autosave(&self, broker: &Broker, mut stop: watch::Receiver<bool>) {
        let mut config = self.config.subscribe();
        let mut last_backup = Instant::now();
        let mut last_changes = 0;
        let mut retry_at = None;
        let mut changes = None;
        loop {
            let (threshold, by_changes, enabled) = {
                let config = config.borrow_and_update();
                (
                    config.autosave_interval,
                    config.autosave_on_changes,
                    config.enabled,
                )
            };
            if *stop.borrow() {
                return;
            }
            tokio::select! {
                biased;
                _ = stop.changed() => return,
                result = config.changed() => {
                    if result.is_err() { return }
                }
                () = async {
                    if !enabled || threshold == 0 {
                        std::future::pending().await
                    } else if by_changes {
                        let changes = changes.get_or_insert_with(|| {
                            broker.watch_persistence_changes().expect("standalone broker")
                        });
                        let _ = changes.wait_for(|&current| current - last_changes >= u64::from(threshold))
                            .await.expect("standalone broker is still running");
                        if let Some(deadline) = retry_at {
                            time::sleep_until(deadline).await;
                        }
                    } else {
                        // src/loop.c: mosquitto__main_loop compares whole seconds with >.
                        time::sleep_until(last_backup + Duration::from_secs(u64::from(threshold) + 1)).await;
                    }
                } => {
                    if !by_changes {
                        last_backup = Instant::now();
                    }
                    match self.backup(broker, false).await {
                        Ok(Some(count)) if by_changes => {
                            // src/loop.c: only automatic backups reset the count.
                            last_changes = count;
                            retry_at = None;
                        }
                        Ok(None) | Err(_) if by_changes => {
                            // The threshold is still met. Back off without waiting
                            // for new MQTT traffic or blocking reload/shutdown.
                            retry_at = Some(Instant::now() + AUTOSAVE_RETRY_DELAY);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

pub(super) async fn migrate_cluster(
    broker: &Broker,
    config: &ServerConfig,
) -> Result<(), ServerError> {
    if config.persistence.enabled
        && broker.can_import_persistence()
        && let Load::Restored(image) = read_mosquitto(config, false).await?
    {
        let counts = image.counts();
        if broker
            .restore_persistence(image)
            .await
            .map_err(ServerError::Cluster)?
        {
            log_imported(&config.persistence.mosquitto_path(), counts);
        }
    }
    Ok(())
}

fn snapshot_path(config: &PersistenceConfig) -> PathBuf {
    // A native image never overwrites the Mosquitto DB: it remains readable by
    // the old broker if the operator rolls back the cutover.
    let mut path = config.mosquitto_path().into_os_string();
    path.push(".mqx");
    path.into()
}

async fn read_mosquitto(config: &ServerConfig, auto_recover: bool) -> Result<Load, ServerError> {
    let path = config.persistence.mosquitto_path();
    let listeners = config.per_listener_settings.then(|| {
        config
            .listeners
            .iter()
            .enumerate()
            .filter(|(_, listener)| {
                listener.protocol != ListenerProtocol::HttpApi && listener.port != 0
            })
            .map(|(index, listener)| (listener.port, index as u64 + 1))
            .collect::<Vec<_>>()
    });
    load_database(IMPORT_FAILED, path, auto_recover, move |path| {
        PersistentState::read_mosquitto(path, |port| match &listeners {
            Some(listeners) => listeners
                .iter()
                .find(|(candidate, _)| *candidate == port)
                .map_or(0, |(_, id)| *id),
            None => 1,
        })
    })
    .await
}

enum Load {
    Missing,
    Restored(PersistentState),
    Discarded,
    Unusable,
}

async fn load_database(
    operation: &'static str,
    path: PathBuf,
    auto_recover: bool,
    read: impl FnOnce(&Path) -> io::Result<Option<PersistentState>> + Send + 'static,
) -> Result<Load, ServerError> {
    file_job(operation, path.clone(), move || {
        let result = if auto_recover {
            read_for_recovery(&path, read)
        } else {
            read(&path)
        };
        match result {
            Ok(Some(image)) => Ok(Load::Restored(image)),
            Ok(None) => Ok(Load::Missing),
            Err(error) if auto_recover && is_corruption(&error) => {
                tracing::warn!(
                    "{operation} '{}': {error}; starting with empty state",
                    path.display()
                );
                match discard_database(&path) {
                    Ok(()) => Ok(Load::Discarded),
                    Err(error) => {
                        tracing::warn!(
                            "Could not discard persistence database '{}': {error}",
                            path.display()
                        );
                        Ok(Load::Unusable)
                    }
                }
            }
            Err(error) => Err(error),
        }
    })
    .await
}

fn read_for_recovery(
    path: &Path,
    read: impl FnOnce(&Path) -> io::Result<Option<PersistentState>>,
) -> io::Result<Option<PersistentState>> {
    // The legacy reader accepts empty files and can optionally follow
    // symlinks. Neither is usable for auto-recovery.
    match database_metadata(path)? {
        Some(metadata) if metadata.len() == 0 => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "persistence database is empty",
        )),
        Some(_) => read(path),
        None => Ok(None),
    }
}

fn is_corruption(error: &io::Error) -> bool {
    let corrupt = |error: &io::Error| {
        matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
        )
    };
    if !corrupt(error) {
        return false;
    }
    // The native decoder can wrap I/O failures in an InvalidData error.
    let mut source = error.get_ref().map(|error| error as &dyn std::error::Error);
    while let Some(cause) = source {
        if cause
            .downcast_ref::<io::Error>()
            .is_some_and(|error| !corrupt(error))
        {
            return false;
        }
        source = cause.source();
    }
    true
}

fn discarded_path(path: &Path) -> PathBuf {
    let mut discarded = path.as_os_str().to_owned();
    discarded.push(".discarded");
    discarded.into()
}

fn discard_database(path: &Path) -> io::Result<()> {
    if database_metadata(path)?.is_some() {
        let discarded = discarded_path(path);
        database_metadata(&discarded)?;
        #[cfg(unix)]
        let directory = fs::File::open(
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        fs::rename(path, discarded)?;
        #[cfg(unix)]
        directory.sync_all()?;
    }
    Ok(())
}

fn database_metadata(path: &Path) -> io::Result<Option<fs::Metadata>> {
    let invalid = |reason| io::Error::new(io::ErrorKind::InvalidData, reason);
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(Some(metadata)),
        Ok(metadata) if metadata.is_symlink() => Err(invalid("persistence database is a symlink")),
        Ok(_) => Err(invalid("persistence database is not a regular file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

async fn write_snapshot(path: PathBuf, state: PersistentState) -> Result<(), ServerError> {
    // src/persist_write.c: persist__backup logs before opening the file.
    tracing::info!("Saving in-memory database to {}.", path.display());
    file_job(
        "Error during saving in-memory database",
        path.clone(),
        move || state.write_snapshot(&path),
    )
    .await
}

async fn file_job<T: Send + 'static>(
    operation: &'static str,
    path: PathBuf,
    work: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> Result<T, ServerError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(io::Error::other)
        .flatten()
        .map_err(|source| ServerError::File {
            operation,
            path,
            source,
        })
}

fn log_restored(counts: PersistenceCounts) {
    // src/persist_read.c: persist__restore reports counts by record type.
    tracing::info!("Restored {} base messages", counts.messages);
    tracing::info!("Restored {} retained messages", counts.retained);
    tracing::info!("Restored {} clients", counts.sessions);
    tracing::info!("Restored {} subscriptions", counts.subscriptions);
    tracing::info!("Restored {} client messages", counts.client_messages);
}

fn log_imported(path: &Path, counts: PersistenceCounts) {
    tracing::info!(target: "mqx::notice", "Imported Mosquitto persistence database from {}.", path.display());
    log_restored(counts);
}
