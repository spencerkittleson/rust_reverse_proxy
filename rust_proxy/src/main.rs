use rust_proxy::*;

#[cfg(windows)]
use rust_proxy::windows;

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
    
    info!("Proxy server starting on {} (max connections: {})", addr, MAX_CONNECTIONS);
    info!("Log level set to: {}", args.log_level);
    info!("Host configured: {}", args.host);
    info!("Port configured: {}", args.port);

    loop {
        let (client_socket, _) = listener.accept().await?;
        let permit = semaphore.clone().acquire_owned().await?;
        
        tokio::spawn(async move {
            let _permit = permit; // Hold permit until task completes
            if let Err(e) = handle_client(client_socket).await {
                error!("Error handling client: {}", e);
            }
        });
    }
}