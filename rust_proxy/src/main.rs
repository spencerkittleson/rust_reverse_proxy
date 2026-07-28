use rust_proxy::*;
use tokio::signal;

#[cfg(windows)]
use rust_proxy::windows;

async fn accept_and_spawn(
    listener: &TcpListener,
    semaphore: &Arc<Semaphore>,
    stats: &Arc<ProxyStats>,
    config: &Arc<RuntimeConfig>,
) {
    let (client_socket, _) = match listener.accept().await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Accept error: {}", e);
            return;
        }
    };
    let permit = match semaphore.clone().acquire_owned().await {
        Ok(p) => p,
        Err(e) => {
            error!("Semaphore error: {}", e);
            return;
        }
    };
    let stats_clone = stats.clone();
    let config_clone = config.clone();

    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = handle_client(client_socket, stats_clone, config_clone).await {
            error!("Error handling client: {}", e);
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), ProxyError> {
    let args = Args::parse();
    
    // Initialize logger with configurable level
    let log_level = match args.log_level.as_str() {
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => {
            eprintln!("Invalid log level: {}. Using 'info' as default.", args.log_level);
            log::LevelFilter::Info
        }
    };
    
    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    // Validate before touching the host or the network: an invalid credential
    // configuration must not open a firewall port or bind a listener.
    // A set-but-empty RUST_PROXY_AUTH means "no credential", not an empty one.
    let env_auth = std::env::var(AUTH_ENV_VAR)
        .ok()
        .filter(|v| !v.trim().is_empty());
    let config = match build_runtime_config(&args, env_auth) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("Configuration error: {e}");
            std::process::exit(2);
        }
    };

    #[cfg(windows)]
    {
        if let Err(e) = windows::setup_windows_environment(args.port) {
            warn!("Windows environment setup encountered issues: {}", e);
            info!("The proxy will continue, but some optimizations may not be active");
        }
    }
    
    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr).await?;
    
    // Use semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    
    // Initialize statistics
    let stats = Arc::new(ProxyStats::new());
    let stats_logger = stats.clone();

    stats.set_fallback_active(args.rewrite_fallback);
    if args.rewrite_fallback {
        warn!("--rewrite-fallback is enabled: requests that fail rewriting will be");
        warn!("forwarded unrewritten, revealing proxy presence to the origin.");
    }

    stats.set_anonymous_active(config.auth.is_none());
    if config.auth.is_none() {
        warn!("No credential is configured: any client that can reach {} may relay through this proxy.", addr);
        if config.allow_from.is_empty() {
            warn!("No --allow-from restriction is set either, so that is every host that can reach it.");
        }
    }
    
    // Start periodic statistics logging task
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(180)); // Log every 3 minutes
        interval.tick().await; // Skip first immediate tick
        
        loop {
            interval.tick().await;
            stats_logger.log_stats();
        }
    });
    
    info!("Proxy server starting on {} (max connections: {})", addr, MAX_CONNECTIONS);
    info!("Log level set to: {}", args.log_level);
    info!("Host configured: {}", args.host);
    info!("Port configured: {}", args.port);
    info!("Statistics logging enabled (every 3 minutes in INFO mode)");

    let stats_for_accept = stats.clone();
    let sem_for_accept = semaphore.clone();
    tokio::select! {
        _ = async {
            loop {
                accept_and_spawn(&listener, &sem_for_accept, &stats_for_accept, &config).await;
            }
        } => {},
        _ = signal::ctrl_c() => {
            info!("Shutdown signal received. Draining active connections...");
        }
    }

    // Listener is dropped here, accept loop stops

    let drain_ok = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if stats.active_connections.load(Ordering::Relaxed) == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }).await;

    if drain_ok.is_ok() {
        info!("All connections drained. Shutting down.");
    } else {
        warn!("Shutdown timed out with {} active connections. Forcing shutdown.",
            stats.active_connections.load(Ordering::Relaxed));
    }
    
    Ok(())
}