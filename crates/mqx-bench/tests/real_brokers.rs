use std::{path::PathBuf, time::Duration};

use mqx_bench::{ComparisonOptions, Load, Pattern, Quality, compare};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Mosquitto 2.1.4 and cargo build --release -p mqx-server"]
async fn qos1_workload_loses_no_messages_on_any_broker() {
    let state = tempfile::tempdir().unwrap();
    let options = ComparisonOptions {
        state_dir: PathBuf::from(state.path()),
        broker_workers: 2,
    };
    let load = Load {
        publishers: 4,
        subscribers: 4,
        pattern: Pattern::OneToOne,
        qos: Quality::Qos1,
        payload_bytes: 256,
        rate: Some(100),
        duration: Duration::from_secs(5),
        // A healthy publisher can finish immediately; the full drain must
        // still run, even when it exceeds the MQTT client's shutdown timeout.
        drain: Duration::from_secs(11),
        clean_session: true,
        inflight: 20,
    };
    let rows = compare(&options, &[load]).await.unwrap();
    assert_eq!(rows.len(), 3);
    for row in rows {
        let result = row.result;
        assert!(result.published >= 450, "{}: {result:?}", row.broker);
        assert_eq!(
            result.acknowledged,
            Some(result.published),
            "{}",
            row.broker
        );
        assert_eq!(result.lost, 0, "{}: {result:?}", row.broker);
        assert_eq!(result.duplicates, 0, "{}: {result:?}", row.broker);
        assert_eq!(
            result.delivery_latency.samples, result.published,
            "{}",
            row.broker
        );
    }
}
