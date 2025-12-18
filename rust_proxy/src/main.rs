use rust_proxy::*;

#[cfg(windows)]
fn setup_firewall_rule(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;
    
    let output = Command::new("netsh")
        .args(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name=\"Open Port {}\"", port),
            "dir=in",
            "action=allow",
            "protocol=TCP",
            &format!("localport={}", port)
        ])
        .output()?;
    
    if output.status.success() {
        info!("Windows firewall rule added for port {}", port);
    } else {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to add firewall rule: {}", error_msg);
    }
    
    Ok(())
}

#[cfg(windows)]
fn ensure_private_network() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;
    
    // Set network profile to private for all network interfaces
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            "Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private"
        ])
        .output()?;
    
    if output.status.success() {
        info!("Network profiles set to Private mode");
    } else {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to set network profiles to Private: {}", error_msg);
        
        // Fallback: Try netsh method
        let netsh_output = Command::new("netsh")
            .args(&["firewall", "set", "profile", "type", "private"])
            .output()?;
        
        if netsh_output.status.success() {
            info!("Firewall profile set to Private using netsh");
        } else {
            let netsh_error = String::from_utf8_lossy(&netsh_output.stderr);
            warn!("Fallback netsh method also failed: {}", netsh_error);
        }
    }
    
    Ok(())
}

#[cfg(windows)]
fn disable_lid_close_action() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;
    
    // Disable lid close action for both battery and plugged in modes
    let commands = vec![
        ("battery", "powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0"),
        ("plugged", "powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0"),
    ];
    
    for (mode, command) in commands {
        let output = Command::new("cmd")
            .args(&["/C", command])
            .output()?;
        
        if output.status.success() {
            info!("Disabled lid close action for {} mode", mode);
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to disable lid close action for {}: {}", mode, error_msg);
        }
    }
    
    // Apply the power scheme settings
    let apply_output = Command::new("cmd")
        .args(&["/C", "powercfg /setactive SCHEME_CURRENT"])
        .output()?;
    
    if apply_output.status.success() {
        info!("Applied power scheme settings");
    } else {
        let error_msg = String::from_utf8_lossy(&apply_output.stderr);
        warn!("Failed to apply power scheme: {}", error_msg);
    }
    
    Ok(())
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
    
    #[cfg(windows)]
    {
        if let Err(e) = disable_lid_close_action() {
            warn!("Failed to disable lid close action: {}", e);
        }
        
        if let Err(e) = ensure_private_network() {
            warn!("Failed to set network to private mode: {}", e);
        }
        
        if let Err(e) = setup_firewall_rule(args.port) {
            warn!("Failed to setup Windows firewall rule: {}", e);
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