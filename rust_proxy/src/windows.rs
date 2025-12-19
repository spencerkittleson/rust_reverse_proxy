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
    
    // Batch PowerShell commands for network and firewall setup
    let powershell_script = format!(
        r#"
# Set network profiles to private
try {{ Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue }}
catch {{ Write-Host "PowerShell network profile setup failed" }}

# Add firewall rule
try {{ New-NetFirewallRule -DisplayName "Open Port {port}" -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow -ErrorAction SilentlyContinue }}
catch {{ 
    # Fallback to netsh if PowerShell fails
    netsh advfirewall firewall delete rule name="Open Port {port}" 2>$null
    netsh advfirewall firewall add rule name="Open Port {port}" dir=in action=allow protocol=TCP localport={port}
}}

# Configure power settings
try {{
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
    powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
    powercfg /setactive SCHEME_CURRENT
    Write-Host "Power settings configured"
}} catch {{ Write-Host "Power configuration failed" }}
"#,
        port = port
    );
    
    match execute_powershell_script(&powershell_script) {
        Ok(output) => {
            info!("Windows environment setup completed successfully");
            debug!("Setup output: {}", output.trim());
        }
        Err(e) => {
            warn!("PowerShell setup partially failed: {}", e);
            
            // Fallback to individual commands if PowerShell script fails
            info!("Attempting fallback command execution...");
            
            let fallback_commands = vec![
                &format!("netsh advfirewall firewall delete rule name=\"Open Port {}\" 2>nul", port),
                &format!("netsh advfirewall firewall add rule name=\"Open Port {}\" dir=in action=allow protocol=TCP localport={}", port, port),
                "powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0",
                "powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0", 
                "powercfg /setactive SCHEME_CURRENT"
            ];
            
            if let Err(cmd_err) = execute_cmd_batch(&fallback_commands) {
                warn!("Fallback commands also failed: {}", cmd_err);
                return Err(format!("All Windows setup methods failed. Last error: {}", cmd_err).into());
            } else {
                info!("Fallback commands completed successfully");
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