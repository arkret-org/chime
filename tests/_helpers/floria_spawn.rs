//! chime-local floria spawn helper for live-gateway integration tests.

#![allow(dead_code)]

use std::{
    env,
    fs::File,
    io::Write,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener as TokioTcpListener,
    task::JoinHandle,
};

pub struct SpawnedFloria {
    pub base_url: String,
    config_path: PathBuf,
    child: Option<Child>,
    sink_shutdown: Arc<AtomicBool>,
    sink_task: Option<JoinHandle<()>>,
}

impl SpawnedFloria {
    pub fn url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{path}", self.base_url)
        } else {
            format!("{}/{path}", self.base_url)
        }
    }
}

impl Drop for SpawnedFloria {
    fn drop(&mut self) {
        self.sink_shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.sink_task.take() {
            handle.abort();
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_file(&self.config_path);
    }
}

pub async fn spawn_floria() -> Option<SpawnedFloria> {
    let floria_bin = locate_floria_binary()?;
    let bind_port = free_port().ok()?;
    let bind_addr = format!("127.0.0.1:{bind_port}");
    let base_url = format!("http://{bind_addr}");

    let sink_port = free_port().ok()?;
    let sink_shutdown = Arc::new(AtomicBool::new(false));
    let sink_task = spawn_sink(sink_port, sink_shutdown.clone()).await?;
    let config_path = render_floria_config(bind_port, sink_port).ok()?;

    let mut command = Command::new(&floria_bin);
    command
        .env("SOFLARE_CONF", &config_path)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = command.spawn().ok()?;
    let handle = SpawnedFloria {
        base_url,
        config_path,
        child: Some(child),
        sink_shutdown,
        sink_task: Some(sink_task),
    };

    if !wait_for_health(&handle.base_url, Duration::from_secs(30)).await {
        drop(handle);
        return None;
    }

    Some(handle)
}

fn locate_floria_binary() -> Option<PathBuf> {
    if let Ok(value) = env::var("FLORIA_BIN")
        && !value.trim().is_empty()
    {
        let candidate = PathBuf::from(value);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    let exe_name = if cfg!(windows) {
        "floria.exe"
    } else {
        "floria"
    };
    let chime_manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = chime_manifest.parent()?;
    let candidate = workspace_root
        .join("floria")
        .join("target")
        .join("debug")
        .join(exe_name);
    candidate.is_file().then_some(candidate)
}

fn render_floria_config(bind_port: u16, sink_port: u16) -> std::io::Result<PathBuf> {
    let body = format!(
        "http:\n  bind_addresses:\n    - 127.0.0.1\n  port: {bind_port}\n  notify_dedup_ttl_seconds: 0\n  notify_dedup:\n    backend: memory\n    key_prefix: chime-live-floria\n  notify_auth: {{}}\n  notify_rate_limits:\n    window_seconds: 60\n\napps:\n  chime.live.placeholder:\n    type: custom\n    url: http://127.0.0.1:{sink_port}/chime-live-floria-sink\n"
    );
    let path = env::temp_dir().join(format!(
        "chime-live-floria-{}-{}.yaml",
        std::process::id(),
        bind_port
    ));
    let mut file = File::create(&path)?;
    file.write_all(body.as_bytes())?;
    file.flush()?;
    Ok(path)
}

async fn spawn_sink(port: u16, shutdown: Arc<AtomicBool>) -> Option<JoinHandle<()>> {
    let listener = TokioTcpListener::bind(("127.0.0.1", port)).await.ok()?;
    let task = tokio::spawn(async move {
        loop {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }

            match tokio::time::timeout(Duration::from_millis(250), listener.accept()).await {
                Ok(Ok((mut socket, _))) => {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 2048];
                        let _ =
                            tokio::time::timeout(Duration::from_millis(500), socket.read(&mut buf))
                                .await;
                        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = socket.shutdown().await;
                    });
                }
                Ok(Err(_)) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(_) => {}
            }
        }
    });
    Some(task)
}

fn free_port() -> std::io::Result<u16> {
    let listener = StdTcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

async fn wait_for_health(base_url: &str, timeout: Duration) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };
    let url = format!("{base_url}/health");
    let cutoff = Instant::now() + timeout;
    while Instant::now() < cutoff {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return true,
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
    false
}
