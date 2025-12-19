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
    if !is_running_as_admin() {
        warn!("Not running as administrator. Some Windows optimizations may be skipped.");
        info!("For full functionality, run as administrator or enable specific UAC prompts.");
    }
    
    info!("Setting up Windows environment optimizations...");
    
    // Use single elevated PowerShell session to minimize UAC prompts
    let elevated_script = format!(
        r#"
# Start elevated PowerShell session if not already elevated
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {{
    Write-Host "Not running as administrator - some optimizations skipped"
    exit 0
}}

Write-Host "Running with administrator privileges - applying all optimizations"

# Network and firewall setup (non-UAC intensive)
try {{
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
    Write-Host "Network profiles set to Private"
}} catch {{ Write-Host "Network setup failed" }}

try {{
    New-NetFirewallRule -DisplayName "Open Port {port}" -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow -ErrorAction SilentlyContinue
    Write-Host "Firewall rule added for port {port}"
}} catch {{ 
    try {{
        netsh advfirewall firewall delete rule name="Open Port {port}" 2>$null
        netsh advfirewall firewall add rule name="Open Port {port}" dir=in action=allow protocol=TCP localport={port}
        Write-Host "Firewall rule added via netsh"
    }} catch {{ Write-Host "Firewall setup failed" }}
}}

# Power settings - use a single elevated command to minimize prompts
try {{
    # Create a temporary script to run all power commands at once
    $powerScript = @"
powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
powercfg /setactive SCHEME_CURRENT
"@
    
    # Run power commands in a single elevated process
    Start-Process cmd.exe -ArgumentList "/c", $powerScript -Verb RunAs -Wait -WindowStyle Hidden
    Write-Host "Power settings configured"
}} catch {{ 
    # Fallback: try non-elevated power settings (may work for some users)
    try {{
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0 2>$null
        powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0 2>$null
        powercfg /setactive SCHEME_CURRENT 2>$null
        Write-Host "Power settings configured (non-elevated)"
    }} catch {{ Write-Host "Power configuration failed" }}
}}

Write-Host "Windows environment setup completed"
"#,
        port = port
    );
    
    match execute_powershell_script(&elevated_script) {
        Ok(output) => {
            info!("Windows environment setup completed successfully");
            debug!("Setup output: {}", output.trim());
        }
        Err(e) => {
            warn!("PowerShell setup failed: {}", e);
            
            // Minimal fallback - only essential firewall rule
            info!("Attempting minimal firewall setup...");
            
            let firewall_script = format!(
                r#"
# Minimal firewall setup
try {{
    New-NetFirewallRule -DisplayName "Open Port {}" -Direction Inbound -Protocol TCP -LocalPort {} -Action Allow -ErrorAction SilentlyContinue
    Write-Host "Firewall rule added successfully"
}} catch {{
    netsh advfirewall firewall delete rule name="Open Port {}" 2>$null
    netsh advfirewall firewall add rule name="Open Port {}" dir=in action=allow protocol=TCP localport={}
    Write-Host "Firewall rule added via netsh"
}}
"#,
                port, port, port, port, port
            );
            
            if let Err(fw_err) = execute_powershell_script(&firewall_script) {
                warn!("Firewall setup also failed: {}", fw_err);
            }
        }
    }
    
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