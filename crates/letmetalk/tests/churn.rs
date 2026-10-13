mod common;

use std::io;
use std::time::{Duration, Instant};

use common::{Carrier, Hub};
use futures::future::join_all;
use letmetalk::{Admit, Endpoint, PublicKey, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn tasks() -> usize {
    tokio::runtime::Handle::current().metrics().num_alive_tasks()
}

fn fds() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

/// Waits until the runtime's tasks and this process's fds are back to their counts before any link.
async fn settle(tasks_before: usize, fds_before: usize) -> (usize, usize) {
    let start = Instant::now();
    loop {
        let (t, f) = (tasks(), fds());
        if (t <= tasks_before && f <= fds_before) || start.elapsed() > Duration::from_secs(20) {
            return (t, f);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn serve(b: Endpoint) {
    while let Some(mut stream) = b.accept().await {
        tokio::spawn(async move {
            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();
        });
    }
}

async fn round_trip(a: &Endpoint, to: PublicKey) -> io::Result<()> {
    let mut stream = a.connect(to, "echo").await?;
    stream.write_all(b"ping").await?;
    stream.shutdown().await?;
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await?;
    assert_eq!(echoed, b"ping");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn churned_links_and_concurrent_connects_leave_no_tasks_or_sockets() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = Endpoint::new(a_key.clone(), Carrier::join(&hub, &a_key), |_| Admit::Direct);
    let b = Endpoint::new(b_key.clone(), Carrier::join(&hub, &b_key), |_| Admit::Direct);
    tokio::spawn(serve(b));
    let (tasks_before, fds_before) = (tasks(), fds());

    for _ in 0..10 {
        round_trip(&a, b_key.public()).await.unwrap();
        a.disconnect(b_key.public());
    }
    let churned = settle(tasks_before, fds_before).await;

    for _ in 0..3 {
        let trips = join_all((0..8).map(|_| round_trip(&a, b_key.public()))).await;
        assert!(trips.iter().all(Result::is_ok));
        a.disconnect(b_key.public());
    }
    let concurrent = settle(tasks_before, fds_before).await;

    eprintln!("tasks/fds before {tasks_before}/{fds_before}, after churn {churned:?}, after concurrent {concurrent:?}");
    assert!(churned.0 <= tasks_before && churned.1 <= fds_before, "churn left {churned:?}");
    assert!(concurrent.0 <= tasks_before && concurrent.1 <= fds_before, "concurrent connects left {concurrent:?}");
}
