use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use mqx_broker::{Broker, PersistenceCounts, PersistentState};
use mqx_server::{ListenerProtocol, PersistenceConfig, ServerConfig, ServerError};
use tokio::{
    sync::{Mutex, watch},
    time::{self, Instant},
};

pub(super) struct Persistence {
    config: watch::Sender<PersistenceConfig>,
    writer: Mutex<()>,
}

impl Persistence {
    pub(super) fn new(config: PersistenceConfig) -> Self {
        Self {
            config: watch::Sender::new(config),
            writer: Mutex::new(()),
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
        let path = native.clone();
        let image = file_job(
            "Unable to restore persistent database",
            path.clone(),
            move || PersistentState::read_snapshot(&path),
        )
        .await?;
        if let Some(image) = image {
            let counts = image.counts();
            broker
                .restore_persistence(image)
                .await
                .map_err(ServerError::Cluster)?;
            log_restored(counts);
        } else if let Some(image) = read_mosquitto(config).await? {
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

    pub(super) async fn backup(&self, broker: &Broker, shutdown: bool) -> Option<u64> {
        let _write = self.writer.lock().await;
        let path = {
            let config = self.config.borrow();
            if !config.enabled {
                return None;
            }
            snapshot_path(&config)
        };
        let (changes, state) = broker.persistence_snapshot(shutdown)?;
        if let Err(error) = write_snapshot(path, state).await {
            tracing::error!("{error}");
        }
        Some(changes)
    }

    pub(super) async fn autosave(&self, broker: &Broker, mut stop: watch::Receiver<bool>) {
        let mut config = self.config.subscribe();
        let mut last_backup = Instant::now();
        let mut last_changes = 0;
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
                    } else {
                        // src/loop.c: mosquitto__main_loop compares whole seconds with >.
                        time::sleep_until(last_backup + Duration::from_secs(u64::from(threshold) + 1)).await;
                    }
                } => {
                    if !by_changes {
                        last_backup = Instant::now();
                    }
                    if let Some(count) = self.backup(broker, false).await && by_changes {
                        // src/loop.c: only automatic backups reset the count.
                        last_changes = count;
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
        && let Some(image) = read_mosquitto(config).await?
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

async fn read_mosquitto(config: &ServerConfig) -> Result<Option<PersistentState>, ServerError> {
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
    file_job(
        "Unable to import Mosquitto persistence database",
        path.clone(),
        move || {
            PersistentState::read_mosquitto(&path, |port| match &listeners {
                Some(listeners) => listeners
                    .iter()
                    .find(|(candidate, _)| *candidate == port)
                    .map_or(0, |(_, id)| *id),
                None => 1,
            })
        },
    )
    .await
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
