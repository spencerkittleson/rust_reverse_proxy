#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use log::{info, warn, debug};

#[cfg(windows)]
pub fn is_running_as_admin() -> bool {
    use std::process::Command;
    
    // Try to run a command that requires admin privileges
    let output = Command::new("net")
        .args(&["session"])
        .output();
    
    match output {
        Ok(result) => result.status.success(),
        Err(_) => false,
    }
}

#[cfg(windows)]
pub fn execute_powershell_script(script: &str) -> Result<String, Box<dyn std::error::Error>> {
    debug!("Executing PowerShell script: {}", script);
    
    let output = Command::new("powershell")
        .args(&["-ExecutionPolicy", "Bypass", "-Command", script])
        .output()?;
    
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("PowerShell output: {}", stdout.trim());
        Ok(stdout.to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("PowerShell failed: {}", stderr.trim());
        Err(format!("PowerShell command failed: {}", stderr).into())
    }
}

#[cfg(windows)]
pub fn execute_cmd_batch(commands: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let batch_script = commands.join(" && ");
    debug!("Executing CMD batch: {}", batch_script);
    
    let output = Command::new("cmd")
        .args(&["/C", &batch_script])
        .output()?;
    
    if output.status.success() {
        info!("All CMD commands executed successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("CMD batch failed: {}", stderr.trim());
        Err(format!("CMD batch failed: {}", stderr).into())
    }
}

#[cfg(windows)]
pub fn setup_windows_environment(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    info!("Setting up Windows environment optimizations (UAC-free mode)...");
    
    // Check admin status without triggering UAC
    let is_admin = is_running_as_admin();
    if !is_admin {
        info!("Running without administrator privileges. Only basic optimizations will be applied.");
    } else {
        info!("Running with administrator privileges.");
    }
    
    // Basic network profile setup (UAC-free)
    let network_script = format!(
        r#"
# Network profile setup (non-elevated)
try {{
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
    Write-Host "Network profiles set to Private"
}} catch {{ Write-Host "Network setup failed" }}
"#,
    );
    
    // Firewall setup with netsh (less likely to trigger UAC than New-NetFirewallRule)
    let firewall_script = format!(
        r#"
# Firewall setup using netsh (UAC-free approach)
try {{
    netsh advfirewall firewall delete rule name="Open Port {}" 2>$null
    netsh advfirewall firewall add rule name="Open Port {}" dir=in action=allow protocol=TCP localport={}
    Write-Host "Firewall rule added via netsh for port {}"
}} catch {{ Write-Host "Firewall setup failed" }}
"#,
        port, port, port, port
    );
    
    // Power settings (non-elevated only)
    let power_script = r#"
# Power settings (non-elevated only)
try {
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0 2>$null
    powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0 2>$null
    powercfg /setactive SCHEME_CURRENT 2>$null
    Write-Host "Power settings configured (non-elevated)"
} catch { Write-Host "Power configuration requires admin privileges - skipping" }
"#;
    
    // Execute all scripts without any elevation attempts
    if let Err(e) = execute_powershell_script(&network_script) {
        debug!("Network setup failed: {}", e);
    }
    
    if let Err(e) = execute_powershell_script(&firewall_script) {
        debug!("Firewall setup failed: {}", e);
    }
    
    if let Err(e) = execute_powershell_script(power_script) {
        debug!("Power setup failed: {}", e);
    }
    
    info!("Windows environment setup completed (UAC-free)");
    Ok(())
}

#[cfg(not(windows))]
pub fn setup_windows_environment(_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(not(windows))]
pub fn is_running_as_admin() -> bool {
    true
}