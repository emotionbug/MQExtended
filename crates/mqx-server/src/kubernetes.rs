use std::{collections::BTreeMap, env, error::Error, net::Ipv6Addr, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, Response, body::Incoming, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use mqx_cluster::{MemberRole, MembershipControl, MembershipStatus, NodeStatus};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    fs,
    net::TcpStream,
    time::{self, Instant, MissedTickBehavior},
};
use tokio_rustls::TlsConnector;

const TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const NAMESPACE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
const ROUND_INTERVAL: Duration = Duration::from_secs(30);
const ROUND_TIMEOUT: Duration = Duration::from_secs(20);
const WARN_INTERVAL: Duration = Duration::from_secs(60);
const MAX_OBJECT_BYTES: usize = 2 * 1024 * 1024;

type Result<T, E = Box<dyn Error + Send + Sync>> = std::result::Result<T, E>;

pub(crate) fn valid_dns_label(name: &str, max: usize) -> bool {
    let alphanumeric = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let bytes = name.as_bytes();
    bytes.len() <= max
        && bytes.first().is_some_and(alphanumeric)
        && bytes.last().is_some_and(alphanumeric)
        && bytes.iter().all(|byte| alphanumeric(byte) || *byte == b'-')
}

/// MQExtended uses in-cluster credentials only; a failed poll never interrupts serving.
pub async fn run_kubernetes_rollout(
    node_id: u64,
    statefulsets: BTreeMap<u64, String>,
    membership: MembershipControl,
) {
    let resources = statefulsets
        .into_iter()
        .map(|(id, name)| (id, format!("{name}-0"), name))
        .collect::<Vec<_>>();
    let mut ticks = time::interval(ROUND_INTERVAL);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut api = None;
    let mut last_warning: Option<Instant> = None;
    loop {
        ticks.tick().await;
        let round = async {
            let api = match &api {
                Some(api) => api,
                None => &*api.insert(InCluster::load().await?),
            };
            api.poll(node_id, &resources, &membership).await
        };
        let result = match time::timeout(ROUND_TIMEOUT, round).await {
            Ok(result) => result,
            Err(error) => Err(error.into()),
        };
        if let Err(error) = result {
            // Allow a replaced CA bundle to be picked up after a TLS failure.
            api = None;
            if last_warning.is_none_or(|when| when.elapsed() >= WARN_INTERVAL) {
                tracing::warn!(%error, "Kubernetes voter rollout poll failed");
                last_warning = Some(Instant::now());
            }
        }
    }
}

struct InCluster {
    host: String,
    port: u16,
    authority: String,
    namespace: String,
    server_name: ServerName<'static>,
    tls: TlsConnector,
}

impl InCluster {
    async fn load() -> Result<Self> {
        let host = env::var("KUBERNETES_SERVICE_HOST")?;
        let port = env::var("KUBERNETES_SERVICE_PORT")?.parse()?;
        let server_name = ServerName::try_from(host.clone())?;
        let authority = if host.parse::<Ipv6Addr>().is_ok() {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let namespace = fs::read_to_string(NAMESPACE).await?;
        let namespace = namespace.trim().to_owned();
        if !valid_dns_label(&namespace, 63) {
            return Err("Invalid namespace in projected Kubernetes service account volume".into());
        }
        let pem = fs::read(CA).await?;
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&pem) {
            roots.add(cert?)?;
        }
        if roots.is_empty() {
            return Err("No CA certificates in projected Kubernetes service account volume".into());
        }
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        Ok(Self {
            host,
            port,
            authority,
            namespace,
            server_name,
            tls: TlsConnector::from(Arc::new(config)),
        })
    }

    async fn poll(
        &self,
        node_id: u64,
        resources: &[(u64, String, String)],
        membership: &MembershipControl,
    ) -> Result<()> {
        let token = fs::read_to_string(TOKEN).await?;
        let token = token.trim();
        if token.is_empty() {
            return Err("Empty token in projected Kubernetes service account volume".into());
        }
        let mut authorization = header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        authorization.set_sensitive(true);
        let stream = TcpStream::connect((self.host.as_str(), self.port)).await?;
        let stream = self.tls.connect(self.server_name.clone(), stream).await?;
        let (sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
        let mut api = Api {
            sender,
            authority: &self.authority,
            authorization,
        };
        let check = check(&mut api, &self.namespace, node_id, resources, membership);
        tokio::pin!(check);
        tokio::select! {
            result = &mut check => result,
            // Finish receiving the last response or surface the closed connection.
            _ = connection => check.await,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteOptions<'a> {
    api_version: &'static str,
    kind: &'static str,
    preconditions: Preconditions<'a>,
}

#[derive(Serialize)]
struct Preconditions<'a> {
    uid: &'a str,
}

struct Api<'a> {
    sender: http1::SendRequest<Full<Bytes>>,
    authority: &'a str,
    authorization: header::HeaderValue,
}

impl Api<'_> {
    async fn request(
        &mut self,
        method: Method,
        path: &str,
        body: Bytes,
    ) -> Result<Response<Incoming>> {
        let mut request = Request::builder()
            .method(&method)
            .uri(path)
            .header(header::HOST, self.authority)
            .header(header::ACCEPT, "application/json")
            .header(header::AUTHORIZATION, &self.authorization);
        if !body.is_empty() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        self.sender.ready().await?;
        let response = self
            .sender
            .send_request(request.body(Full::new(body))?)
            .await?;
        if !response.status().is_success() {
            return Err(format!("{method} {path}: HTTP {}", response.status()).into());
        }
        Ok(response)
    }

    async fn get<T: DeserializeOwned>(&mut self, path: &str) -> Result<T> {
        let response = self.request(Method::GET, path, Bytes::new()).await?;
        let body = Limited::new(response.into_body(), MAX_OBJECT_BYTES)
            .collect()
            .await?
            .to_bytes();
        Ok(serde_json::from_slice(&body)?)
    }
}

#[derive(Deserialize)]
struct StatefulSet {
    metadata: StatefulSetMetadata,
    status: Option<StatefulSetStatus>,
}

#[derive(Deserialize)]
struct StatefulSetMetadata {
    generation: u64,
    annotations: Option<StatefulSetAnnotations>,
}

#[derive(Deserialize)]
struct StatefulSetAnnotations {
    #[serde(rename = "mqextended.io/rollout-generation")]
    rollout_generation: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatefulSetStatus {
    observed_generation: Option<u64>,
    update_revision: Option<String>,
}

#[derive(Deserialize)]
struct Pod {
    metadata: PodMetadata,
    status: Option<PodStatus>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodMetadata {
    uid: String,
    deletion_timestamp: Option<String>,
    labels: Option<PodLabels>,
}

#[derive(Deserialize)]
struct PodLabels {
    #[serde(rename = "controller-revision-hash")]
    revision: Option<String>,
}

#[derive(Deserialize)]
struct PodStatus {
    #[serde(default)]
    conditions: Vec<PodCondition>,
}

#[derive(Deserialize)]
struct PodCondition {
    #[serde(rename = "type")]
    kind: String,
    status: String,
}

struct Voter {
    id: u64,
    uid: String,
    update_revision: String,
    revision: String,
    ready: bool,
    terminating: bool,
}

async fn check(
    api: &mut Api<'_>,
    namespace: &str,
    node_id: u64,
    resources: &[(u64, String, String)],
    membership: &MembershipControl,
) -> Result<()> {
    let sets = format!("/apis/apps/v1/namespaces/{namespace}/statefulsets");
    let pods = format!("/api/v1/namespaces/{namespace}/pods");
    let mut generation = None;
    let mut voters = Vec::with_capacity(resources.len());
    for (id, pod_name, set_name) in resources {
        let set: StatefulSet = api.get(&format!("{sets}/{set_name}")).await?;
        let Some(release) = set.metadata.annotations.and_then(|a| a.rollout_generation) else {
            return Ok(());
        };
        // Helm and the independent StatefulSet controllers apply changes at
        // different rates. Do not pick a voter from a mixture of releases.
        match &generation {
            Some(first) if first != &release => return Ok(()),
            Some(_) => {}
            None => generation = Some(release),
        }
        let Some(status) = set
            .status
            .filter(|s| s.observed_generation == Some(set.metadata.generation))
        else {
            return Ok(());
        };
        let Some(update_revision) = status.update_revision.filter(|s| !s.is_empty()) else {
            return Ok(());
        };
        let pod: Pod = api.get(&format!("{pods}/{pod_name}")).await?;
        let Some(revision) = pod
            .metadata
            .labels
            .and_then(|labels| labels.revision)
            .filter(|s| !s.is_empty())
        else {
            return Ok(());
        };
        voters.push(Voter {
            id: *id,
            uid: pod.metadata.uid,
            update_revision,
            revision,
            ready: pod.status.is_some_and(|s| {
                s.conditions
                    .iter()
                    .any(|c| c.kind == "Ready" && c.status == "True")
            }),
            terminating: pod.metadata.deletion_timestamp.is_some(),
        });
    }
    // Avoid taking a membership snapshot when this Pod does not need replacing.
    if !voters
        .iter()
        .any(|v| v.id == node_id && v.revision != v.update_revision)
    {
        return Ok(());
    }
    if let Some(voter) = selected_voter(
        node_id,
        &voters,
        &membership.status(),
        membership.lease_valid_until().is_some(),
    ) {
        let (_, name, _) = resources
            .iter()
            .find(|(id, _, _)| *id == node_id)
            .expect("selected configured voter");
        let options = DeleteOptions {
            api_version: "v1",
            kind: "DeleteOptions",
            preconditions: Preconditions { uid: &voter.uid },
        };
        tracing::info!(
            node_id,
            pod = name,
            from = voter.revision,
            to = voter.update_revision,
            "Kubernetes voter rollout: replacing local Pod"
        );
        api.request(
            Method::DELETE,
            &format!("{pods}/{name}"),
            serde_json::to_vec(&options)?.into(),
        )
        .await?;
    }
    Ok(())
}

fn selected_voter<'a>(
    node_id: u64,
    voters: &'a [Voter],
    membership: &MembershipStatus,
    serving: bool,
) -> Option<&'a Voter> {
    if !serving
        || membership.joint
        || voters
            .iter()
            .any(|v| !v.ready || v.terminating || v.uid.is_empty())
        || membership
            .members
            .values()
            .filter(|m| m.role == MemberRole::Voter)
            .count()
            != voters.len()
        || voters.iter().any(|v| {
            !membership
                .members
                .get(&v.id)
                .is_some_and(|m| m.role == MemberRole::Voter && m.liveness == NodeStatus::Alive)
        })
    {
        return None;
    }
    voters
        .iter()
        .filter(|v| v.revision != v.update_revision)
        .min_by_key(|v| v.id)
        .filter(|v| v.id == node_id)
}

#[cfg(test)]
mod tests {
    use mqx_cluster::MemberStatus;

    use super::*;

    #[test]
    fn rollout_selects_only_the_first_outdated_voter_when_all_are_healthy() {
        let mut voters = [3, 1, 2].map(|id| Voter {
            id,
            uid: id.to_string(),
            update_revision: "new".into(),
            revision: if id == 1 { "new" } else { "old" }.into(),
            ready: true,
            terminating: false,
        });
        let mut membership = MembershipStatus::default();
        for v in &voters {
            membership.members.insert(
                v.id,
                MemberStatus {
                    address: "127.0.0.1:7000".parse().unwrap(),
                    role: MemberRole::Voter,
                    liveness: NodeStatus::Alive,
                },
            );
        }
        assert!(selected_voter(1, &voters, &membership, true).is_none());
        assert!(selected_voter(3, &voters, &membership, true).is_none());
        assert!(selected_voter(2, &voters, &membership, true).is_some());
        voters[1].ready = false;
        assert!(selected_voter(2, &voters, &membership, true).is_none());
        voters[1].ready = true;
        voters[1].terminating = true;
        assert!(selected_voter(2, &voters, &membership, true).is_none());
        voters[1].terminating = false;
        assert!(selected_voter(2, &voters, &membership, false).is_none());
        membership.members.get_mut(&3).unwrap().liveness = NodeStatus::Down;
        assert!(selected_voter(2, &voters, &membership, true).is_none());
    }
}
