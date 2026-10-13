mod common;

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::{Carrier, Hub, round_trip, serve};
use letmetalk::{Admit, Endpoint, IceServer, SecretKey};

/// A coturn with one static user, on free ports, killed when dropped.
struct Coturn {
    child: Child,
    port: u16,
    log: PathBuf,
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Coturn {
    fn start() -> Coturn {
        let (port, relay) = (free_port(), free_port());
        let log = std::env::temp_dir().join(format!("letmetalk-relay-{port}.log"));
        let child = Command::new("turnserver")
            .args([
                "-n",
                "--lt-cred-mech",
                "--user=alice:wonderland",
                "--realm=letmetalk",
                "--no-tls",
                "--no-cli",
                "--verbose",
                "--simple-log",
                "--allow-loopback-peers",
                "--listening-ip=127.0.0.1",
                "--relay-ip=127.0.0.1",
                &format!("--listening-port={port}"),
                &format!("--min-port={relay}"),
                &format!("--max-port={}", relay + 200),
                &format!("--log-file={}", log.display()),
                "--pidfile=/dev/null",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("turnserver on PATH");
        std::thread::sleep(Duration::from_millis(500));
        Coturn { child, port, log }
    }

    fn server(&self) -> IceServer {
        IceServer {
            urls: vec![format!("turn:127.0.0.1:{}?transport=udp", self.port)],
            username: "alice".into(),
            credential: "wonderland".into(),
        }
    }
}

impl Drop for Coturn {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn relayed_links_carry_streams_through_turn_only() {
    let coturn = Coturn::start();
    let hub = Hub::default();
    hub.with_turn(coturn.server());
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = Endpoint::new(a_key.clone(), Carrier::join(&hub, &a_key), |_| Admit::Relayed);
    let b = Endpoint::new(b_key.clone(), Carrier::join(&hub, &b_key), |_| Admit::Relayed);
    tokio::spawn(serve(b));
    round_trip(&a, b_key.public()).await.unwrap();
    let log = std::fs::read_to_string(&coturn.log).unwrap();
    let allocations = log.lines().filter(|line| line.contains("allocation new")).count();
    assert!(allocations >= 2, "coturn logged {allocations} allocations:\n{log}");
}
