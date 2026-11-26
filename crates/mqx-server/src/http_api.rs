use std::{convert::Infallible, fmt::Write as _, path::Path, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    header,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use mqx_broker::{Broker, MOSQUITTO_VERSION, SecurityHandle};
use percent_encoding::percent_decode_str;
use serde_json::json;
use tokio::{fs::File, io::AsyncReadExt};
use tokio_util::io::ReaderStream;

use crate::{Connection, ListenerProtocol, Server, ServerConfig};

type Error = Box<dyn std::error::Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, Error>;

/// The HTTP API shares the listener's reloadable security handle, but does not
/// create MQTT sessions or increment counters when serving HTTP requests.
#[derive(Clone)]
pub struct HttpApi {
    listeners: tokio::sync::watch::Sender<Bytes>,
    copies: Arc<[usize]>,
    anonymous: Arc<[bool]>,
}

impl HttpApi {
    pub fn new(config: &ServerConfig, server: &Server) -> Self {
        let copies: Arc<[_]> = config
            .listeners
            .iter()
            .enumerate()
            .map(|(i, listener)| {
                if config.local_only && listener.protocol == ListenerProtocol::Mqtt {
                    server.listener_socket_count(i)
                } else {
                    1
                }
            })
            .collect();
        let anonymous: Arc<[_]> = config
            .listeners
            .iter()
            .map(|listener| config.allow_anonymous_for(listener))
            .collect();
        let listeners =
            tokio::sync::watch::Sender::new(Self::inventory(config, &copies, &anonymous));
        Self {
            listeners,
            anonymous,
            copies,
        }
    }

    pub fn reload_access(&self, bound: &ServerConfig, fresh: &ServerConfig) {
        let anonymous: Vec<_> = fresh
            .listeners
            .iter()
            .map(|l| fresh.allow_anonymous_for(l))
            .collect();
        self.listeners
            .send_replace(Self::inventory(bound, &self.copies, &anonymous));
    }

    fn inventory(config: &ServerConfig, copies: &[usize], anonymous: &[bool]) -> Bytes {
        // src/http_api.c: http_api__process_listeners reports config order,
        // including its own endpoint, and tests cert/key presence, not handshakes.
        let mut response = String::from("{\n\t\"listeners\":\t[");
        let mut first = true;
        for (index, listener) in config.listeners.iter().enumerate() {
            let protocol = match listener.protocol {
                ListenerProtocol::Mqtt => "mqtt",
                ListenerProtocol::Websockets => "websockets",
                ListenerProtocol::HttpApi => "httpapi",
            };
            let allowed = anonymous[index];
            let tls = listener.tls.certfile.is_some() && listener.tls.keyfile.is_some();
            let mtls = listener.tls.require_certificate;
            // listeners__start_local_only adds a distinct config entry for each
            // MQTT loopback socket that actually opened.
            for _ in 0..copies[index] {
                if !first {
                    response.push_str(", ");
                }
                first = false;
                // src/http_api.c: http_api__process_listeners identifies a
                // Unix listener by its path instead of its zero port.
                if let Some(path) = &listener.unix_socket_path {
                    let path = serde_json::to_string(&path.to_string_lossy()).unwrap();
                    write!(response, "{{\n\t\t\t\"path\":\t{path}").unwrap();
                } else {
                    write!(response, "{{\n\t\t\t\"port\":\t{}", listener.port).unwrap();
                }
                write!(response, ",\n\t\t\t\"protocol\":\t\"{protocol}\",\n\t\t\t\"tls\":\t{tls},\n\t\t\t\"mtls\":\t{mtls},\n\t\t\t\"allow_anonymous\":\t{allowed}\n\t\t}}").unwrap();
            }
        }
        response.push_str("]\n}");
        Bytes::from(response)
    }

    pub async fn serve(
        &self,
        connection: Connection,
        broker: &Broker,
        security: &SecurityHandle,
        ready: &(impl Fn() -> bool + Sync),
    ) -> Result<(), hyper::Error> {
        let root = connection.listener.http_dir.as_deref();
        let anonymous = self.anonymous[connection.listener_index];
        http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(Duration::from_secs(20))
            .serve_connection(
                TokioIo::new(connection.stream),
                service_fn(|request| async move {
                    Ok::<_, Infallible>(
                        self.request(request, broker, security, anonymous, root, ready)
                            .await,
                    )
                }),
            )
            .await
    }

    async fn request(
        &self,
        request: Request<Incoming>,
        broker: &Broker,
        security: &SecurityHandle,
        anonymous: bool,
        root: Option<&Path>,
        ready: &(impl Fn() -> bool + Sync),
    ) -> Response<Body> {
        // src/http_api.c: http_api_handler checks method before credentials.
        if request.method() != Method::GET {
            return respond(StatusCode::METHOD_NOT_ALLOWED, "Invalid HTTP Method\n");
        }
        let path = percent_decode_str(request.uri().path()).decode_utf8_lossy();
        let credentials = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| basic_credentials(value.as_bytes()));
        let pair = credentials.as_deref().and_then(|value| {
            let colon = value.iter().position(|&byte| byte == b':')?;
            Some((&value[..colon], &value[colon + 1..]))
        });
        let (username, password) = match pair {
            Some((user, password)) => {
                let user = user.split(|&byte| byte == 0).next().unwrap();
                let Ok(user) = std::str::from_utf8(user) else {
                    return unauthorized();
                };
                (Some(user), Some(password))
            }
            None => (None, None),
        };
        if !broker
            .http_read_allowed(security, username, password, anonymous, &path)
            .await
        {
            return unauthorized();
        }
        match path.as_ref() {
            "/api/v1/version" => api_response(MOSQUITTO_VERSION),
            "/api/v1/listeners" => api_response(self.listeners.borrow().clone()),
            "/api/v1/systree" => {
                // src/http_api.c: http_api__process_systree; json_help.c:
                // cJSON_AddIntToObject prints signed integer literals without f64 rounding.
                let mut data = String::from("{\n");
                for (index, (name, value)) in broker.sys_tree().entries().enumerate() {
                    if index != 0 {
                        data.push_str(",\n");
                    }
                    write!(data, "\t\"{name}\":\t{value}").unwrap();
                }
                data.push_str("\n}");
                api_response(data)
            }
            "/api/v1/mqx/ready" => {
                let mut response = if ready() {
                    respond(StatusCode::OK, "ready\n")
                } else {
                    respond(StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
                };
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    header::HeaderValue::from_static("no-store"),
                );
                response
            }
            "/api/v1/mqx/cluster" => {
                let data = cluster_status(broker);
                let mut response = api_response(data.to_string());
                response
                    .headers_mut()
                    .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
                response
            }
            "/metrics" => {
                let mut response = respond(StatusCode::OK, prometheus(broker).await);
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8".parse().unwrap(),
                );
                response
            }
            _ if path
                .as_bytes()
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"/api/")) =>
            {
                not_found()
            }
            _ => static_file(root, &path).await,
        }
    }
}

fn cluster_status(broker: &Broker) -> serde_json::Value {
    let Some(metrics) = broker.raft_metrics() else {
        return json!({ "mode": "standalone", "mqx_version": env!("CARGO_PKG_VERSION") });
    };
    let membership = broker
        .cluster_membership()
        .map(|membership| membership.status());
    json!({
        "mode": "cluster",
        "mqx_version": env!("CARGO_PKG_VERSION"),
        "membership": membership,
        "auto_recover": metrics.auto_recover,
        "incarnation": metrics.incarnation,
        "last_survivor_event": metrics.last_survivor_event,
        "raft": {
            "node_id": metrics.node_id,
            "term": metrics.current_term,
            "leader": metrics.leader,
            "running": metrics.running,
            "last_log_index": metrics.last_log_index,
            "committed_index": metrics.committed_index,
            "applied_index": metrics.applied_index,
            "snapshot_index": metrics.snapshot_index,
            "purged_index": metrics.purged_index,
        },
    })
}

async fn prometheus(broker: &Broker) -> String {
    let stats = broker.metrics();
    let mut body = String::new();
    for (metric, kind, value) in [
        ("connections", "gauge", stats.connections),
        ("sessions", "gauge", stats.sessions),
        (
            "messages_received_total",
            "counter",
            stats.messages_received,
        ),
        ("messages_sent_total", "counter", stats.messages_sent),
        ("bytes_received_total", "counter", stats.bytes_received),
        ("bytes_sent_total", "counter", stats.bytes_sent),
        ("retained_messages", "gauge", stats.retained),
        ("subscriptions", "gauge", stats.subscriptions),
        ("shared_subscriptions", "gauge", stats.shared_subscriptions),
    ] {
        writeln!(body, "# TYPE mqx_{metric} {kind}\nmqx_{metric} {value}").unwrap();
    }
    if let Some(metrics) = broker.raft_metrics() {
        for (name, value) in [
            ("mqx_cluster_auto_recover", u64::from(metrics.auto_recover)),
            ("mqx_cluster_incarnation", metrics.incarnation),
            (
                "mqx_storage_available_bytes",
                metrics.storage_available_bytes,
            ),
            ("mqx_storage_reserve_bytes", metrics.storage_reserve_bytes),
        ] {
            writeln!(body, "# TYPE {name} gauge\n{name} {value}").unwrap();
        }
        if let Some(event) = metrics.last_survivor_event {
            let name = "mqx_cluster_last_recovery_timestamp_seconds";
            writeln!(
                body,
                "# TYPE {name} gauge\n{name}{{reason=\"{}\"}} {}",
                event.reason.as_str(),
                event.timestamp_seconds
            )
            .unwrap();
        }
        for (metric, value) in [
            ("commit", metrics.committed_index),
            ("apply", metrics.applied_index),
        ] {
            // Absent progress is not index zero.
            if let Some(value) = value {
                writeln!(
                    body,
                    "# TYPE mqx_raft_{metric}_index gauge\nmqx_raft_{metric}_index {value}"
                )
                .unwrap();
            }
        }
        let name = "mqx_raft_snapshot_size_bytes";
        writeln!(
            body,
            "# TYPE {name} gauge\n{name} {}",
            metrics.snapshot_size_bytes
        )
        .unwrap();
    }
    if let Some(metrics) = broker.wal_metrics().await {
        write_wal_metrics(&mut body, metrics);
    }
    let histogram = stats.proposal_latency;
    let name = "mqx_raft_proposal_duration_seconds";
    writeln!(body, "# TYPE {name} histogram").unwrap();
    for (bound, count) in histogram.buckets {
        writeln!(body, "{name}_bucket{{le=\"{bound}\"}} {count}").unwrap();
    }
    writeln!(
        body,
        "{name}_bucket{{le=\"+Inf\"}} {}\n{name}_sum {}\n{name}_count {}",
        histogram.count, histogram.sum_seconds, histogram.count
    )
    .unwrap();
    body
}

fn write_wal_metrics(body: &mut String, metrics: mqx_cluster::WalMetrics) {
    for (name, value) in [
        (
            "mqx_raft_wal_appended_entries_total",
            metrics.appended_entries,
        ),
        ("mqx_raft_wal_sync_batches_total", metrics.sync_batches),
    ] {
        writeln!(body, "# TYPE {name} counter\n{name} {value}").unwrap();
    }
    for (name, kind, duration) in [
        (
            "mqx_raft_wal_sync_seconds_total",
            "counter",
            metrics.sync_time,
        ),
        ("mqx_raft_wal_sync_max_seconds", "gauge", metrics.sync_max),
        ("mqx_raft_wal_write_max_seconds", "gauge", metrics.write_max),
        (
            "mqx_raft_wal_queue_wait_max_seconds",
            "gauge",
            metrics.queue_wait_max,
        ),
    ] {
        let value = duration.as_secs_f64();
        writeln!(body, "# TYPE {name} {kind}\n{name} {value}").unwrap();
    }
}

fn basic_credentials(value: &[u8]) -> Option<Vec<u8>> {
    let encoded = value.get(6..)?;
    if !value[..6].eq_ignore_ascii_case(b"Basic ") {
        return None;
    }
    STANDARD.decode(encoded).ok()
}

fn unauthorized() -> Response<Body> {
    let mut response = respond(StatusCode::UNAUTHORIZED, "Not authorised\n");
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        "Basic realm=\"Mosquitto API\"".parse().unwrap(),
    );
    response
}

fn not_found() -> Response<Body> {
    respond(StatusCode::NOT_FOUND, "Not found.\n")
}

fn respond(status: StatusCode, body: impl Into<Bytes>) -> Response<Body> {
    let mut response = Response::new(
        Full::new(body.into())
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response
}

fn api_response(body: impl Into<Bytes>) -> Response<Body> {
    let mut response = respond(StatusCode::OK, body);
    response
        .headers_mut()
        .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    response
}

async fn static_file(root: Option<&Path>, url: &str) -> Response<Body> {
    // src/http_api.c: http__canonical_filename resolves links before checking
    // the directory boundary. The explicit root directory's doubled slash
    // never matches the resolved canonical filename.
    let Some(root) = root.filter(|root| root.parent().is_some()) else {
        return not_found();
    };
    if !url.starts_with('/') {
        return not_found();
    }
    let mut requested = root.to_path_buf();
    requested.push(url.trim_start_matches('/'));
    if url.ends_with('/') {
        requested.push("index.html");
    }
    let Ok(path) = tokio::fs::canonicalize(requested).await else {
        return not_found();
    };
    if !path.starts_with(root) || path == root {
        return not_found();
    }
    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        return not_found();
    };
    if !metadata.is_file() {
        return not_found();
    }
    let Ok(file) = File::open(path).await else {
        return not_found();
    };
    let Ok(metadata) = file.metadata().await else {
        return respond(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error.\n",
        );
    };
    if !metadata.is_file() {
        return not_found();
    }
    let stream = ReaderStream::with_capacity(file.take(metadata.len()), 65_536);
    let stream = tokio_stream::StreamExt::map(stream, |chunk| chunk.map(Frame::data));
    let body = StreamBody::new(stream).map_err(Into::into).boxed_unsync();
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, metadata.len().into());
    response
}

#[cfg(test)]
mod metrics_tests {
    use super::*;

    #[test]
    fn wal_metrics_uses_seconds_with_distinct_io_phases() {
        let mut body = String::new();
        write_wal_metrics(
            &mut body,
            mqx_cluster::WalMetrics {
                appended_entries: 15,
                sync_batches: 5,
                sync_time: Duration::from_millis(2_500),
                sync_max: Duration::from_millis(1_500),
                write_max: Duration::from_micros(250),
                queue_wait_max: Duration::from_millis(20),
            },
        );
        for line in [
            "mqx_raft_wal_appended_entries_total 15",
            "mqx_raft_wal_sync_batches_total 5",
            "# TYPE mqx_raft_wal_sync_seconds_total counter",
            "mqx_raft_wal_sync_seconds_total 2.5",
            "mqx_raft_wal_sync_max_seconds 1.5",
            "mqx_raft_wal_write_max_seconds 0.00025",
            "mqx_raft_wal_queue_wait_max_seconds 0.02",
        ] {
            assert!(body.lines().any(|actual| actual == line), "{line}");
        }
    }

    #[tokio::test]
    async fn standalone_scrape_has_no_raft_storage_metrics() {
        let broker = Broker::new(mqx_broker::BrokerConfig::default());
        let body = prometheus(&broker).await;
        assert!(body.contains("mqx_connections"));
        assert!(!body.contains("mqx_raft_wal_"));
        assert!(!body.contains("mqx_raft_snapshot_size_bytes"));
        assert!(!body.contains("mqx_storage_"));
    }

    #[tokio::test]
    async fn cluster_scrape_exposes_storage_gauges() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = mqx_cluster::ClusterConfig::new(
            1,
            "127.0.0.1:0".parse().unwrap(),
            [(1, "127.0.0.1:9001".parse().unwrap())].into(),
            dir.path().to_path_buf(),
            mqx_cluster::ClusterSecurity::InsecurePlaintext,
        );
        config.snapshot_policy = mqx_cluster::SnapshotPolicy::Never;
        let broker = Broker::clustered(mqx_broker::BrokerConfig::default(), config)
            .await
            .unwrap();
        let body = prometheus(&broker).await;
        broker.shutdown_cluster().await.unwrap();
        assert!(body.contains(
            "# TYPE mqx_raft_snapshot_size_bytes gauge\nmqx_raft_snapshot_size_bytes 0\n"
        ));
        for metric in ["mqx_storage_available_bytes", "mqx_storage_reserve_bytes"] {
            assert!(body.contains(&format!("# TYPE {metric} gauge\n{metric} ")));
        }
    }
}
