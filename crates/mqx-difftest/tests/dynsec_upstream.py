"""Run one Mosquitto 2.1.4 dynsec scenario with an explicitly selected broker."""

import runpy
import socket
import sys
import time
from pathlib import Path


def main():
    broker_kind, binary, plugin, path = sys.argv[1:]
    script = Path(path)
    sys.path[:0] = [str(script.parent), str(script.parent.parent)]
    import mosq_paths
    import mosq_test

    mosq_paths.plugin_dynamic_security = Path(plugin)
    upstream_start = mosq_test.start_broker
    children = []

    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        assigned_port = reservation.getsockname()[1]

        def start_broker(filename, *, use_conf, port, **kwargs):
            assert use_conf and port == assigned_port
            conf = Path(filename).with_suffix(".conf")
            text = conf.read_text()
            # Keep the stock scenario off external interfaces. On restart the
            # same config already has the loopback host.
            listener = f"listener {port} 127.0.0.1\n"
            if listener not in text.splitlines(keepends=True):
                original = f"listener {port}\n"
                assert original in text.splitlines(keepends=True), f"{conf}: missing {original!r}"
                conf.write_text(text.replace(original, listener))
            command = [binary, "-c", str(conf)]
            if broker_kind == "Mosquitto":
                command.append("-v")
            reservation.close()
            broker = upstream_start(filename, cmd=command, port=port, check_port=False, **kwargs)
            children.append(broker)
            deadline = time.monotonic() + 10
            while broker.poll() is None and time.monotonic() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        return broker
                except OSError:
                    time.sleep(0.02)
            raise RuntimeError(
                f"Broker did not start (status {broker.poll()}):\n{mosq_test.broker_log(broker)}"
            )

        mosq_test.start_broker = start_broker
        sys.argv = [str(script), str(assigned_port)]
        try:
            runpy.run_path(str(script), run_name="__main__")
        finally:
            for broker in children:
                if broker.poll() is None:
                    broker.kill()
                    broker.wait()


if __name__ == "__main__":
    main()
