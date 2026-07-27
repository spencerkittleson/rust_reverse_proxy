#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use log::{info, warn, debug};
#[cfg(windows)]
use winapi::um::winuser::{
    FindWindowW, MessageBoxW, PostMessageW, IDNO, IDYES, MB_SETFOREGROUND, MB_SYSTEMMODAL,
    MB_YESNO, WM_COMMAND,
};
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::iter::once;

/// How long to wait for a human to answer the setup prompt before giving up.
#[cfg(windows)]
const SETUP_PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Ask whether to run the setup script, auto-declining after
/// `SETUP_PROMPT_TIMEOUT` if nobody answers.
///
/// The dialog must never block startup indefinitely. When the proxy is launched
/// non-interactively (an SSH session, a service, a scheduled task) there may be
/// no desktop to click on, and an unbounded modal would hang the process before
/// it ever binds its port. Timing out and declining is the safe default: setup
/// only applies optional Windows optimizations, so skipping it degrades
/// gracefully, whereas hanging does not.
#[cfg(windows)]
fn prompt_for_setup() -> bool {
    // Dialog-class window, used to find and dismiss our own message box.
    const DIALOG_CLASS: &str = "#32770";
    let message = "Do you want to run the setup script to configure the environment?";
    let title = "rust_proxy Setup";

    let wide = |s: &str| -> Vec<u16> { OsStr::new(s).encode_wide().chain(once(0u16)).collect() };
    let (wide_message, wide_title) = (wide(message), wide(title));
    let (wide_class_find, wide_title_find) = (wide(DIALOG_CLASS), wide(title));

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                wide_message.as_ptr(),
                wide_title.as_ptr(),
                // System-modal and foreground so the prompt is actually visible
                // when a desktop does exist.
                MB_YESNO | MB_SETFOREGROUND | MB_SYSTEMMODAL,
            )
        };
        // A closed receiver just means we already timed out; nothing to do.
        let _ = tx.send(result);
    });

    match rx.recv_timeout(SETUP_PROMPT_TIMEOUT) {
        Ok(result) => result == IDYES,
        Err(_) => {
            info!(
                "Setup prompt unanswered after {}s — continuing without setup.",
                SETUP_PROMPT_TIMEOUT.as_secs()
            );
            // Dismiss the orphaned dialog so it cannot linger on a desktop or
            // keep its thread parked. MB_YESNO has no close button, so WM_CLOSE
            // is ignored; posting the "No" command is what actually dismisses it.
            unsafe {
                let hwnd = FindWindowW(wide_class_find.as_ptr(), wide_title_find.as_ptr());
                if !hwnd.is_null() {
                    PostMessageW(hwnd, WM_COMMAND, IDNO as usize, 0);
                }
            }
            false
        }
    }
}

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
    if prompt_for_setup() {
        info!("User agreed to run setup script.");
        match Command::new("powershell")
            .args(&["-ExecutionPolicy", "Bypass", "-File", "setup.ps1"])
            .status()
        {
            Ok(status) if status.success() => {
                info!("Setup script executed successfully.");
            }
            Ok(status) => {
                warn!("Setup script finished with a non-zero status: {}", status);
            }
            Err(e) => {
                warn!("Failed to execute setup script: {}", e);
            }
        }
    } else {
        info!("User declined to run setup script.");
    }

    if !is_running_as_admin() {
        warn!("Not running as administrator. Some Windows optimizations may be skipped.");
        info!("For full functionality, run as administrator or enable specific UAC prompts.");
    }
    
    info!("Setting up Windows environment optimizations...");
    
    // Use single elevated PowerShell session to minimize UAC prompts
    let elevated_script = build_elevated_script(port);

/// Build the elevated PowerShell setup script.
/// Note: Rust raw string literals use `{{` and `}}` for literal braces,
/// since PowerShell also uses `{}` for script blocks.
fn build_elevated_script(port: u16) -> String {
    format!(
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

# Power settings - try non-elevated first, only elevate if necessary
try {{
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0 2>$null
    powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0 2>$null
    powercfg /setactive SCHEME_CURRENT 2>$null
    Write-Host "Power settings configured (non-elevated)"
}} catch {{
    if ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") {{
        # Only elevate if we're already admin (no UAC prompt)
        try {{
            powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
            powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
            powercfg /setactive SCHEME_CURRENT
            Write-Host "Power settings configured (elevated)"
        }} catch {{ Write-Host "Power configuration failed" }}
    }} else {{
        Write-Host "Power settings require admin privileges - skipping"
    }}
}}

Write-Host "Windows environment setup completed"
"#,
        port = port
    )
}
    
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