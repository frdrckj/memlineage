use clap::Parser;
use memlineage_mcp_proxy::{filter_response, guard, Outcome};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Parser)]
#[command(name = "memlineage-mcp-proxy")]
struct Cli {
    /// Policy file. A broken file quarantines every write.
    #[arg(long)]
    policy: PathBuf,
    /// Audit database.
    #[arg(long, default_value = ".memlineage/audit.db")]
    db: PathBuf,
    #[arg(long, default_value = "")]
    principal: String,
    #[arg(long, default_value = "mcp")]
    session: String,
    /// `user`, `system`, `web`, `document`, or `tool`.
    #[arg(long, default_value = "tool")]
    source: String,
    #[arg(long, default_value = "mcp-memory")]
    source_ref: String,
    /// Memory server command, after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let yaml = std::fs::read_to_string(&cli.policy).map_err(|err| err.to_string())?;
    let firewall =
        memlineage_core::Firewall::open(&yaml, &cli.db).map_err(|err| err.to_string())?;
    let log = memlineage_core::AuditLog::open(&cli.db).map_err(|err| err.to_string())?;
    let program = cli.command.first().ok_or("missing memory server command")?;
    let mut child = Command::new(program)
        .args(&cli.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| err.to_string())?;
    let mut to_child = child.stdin.take().ok_or("memory server stdin")?;
    let mut from_child = BufReader::new(child.stdout.take().ok_or("memory server stdout")?);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|err| err.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let incoming = format!("{line}\n");
        match guard(
            &firewall,
            &cli.principal,
            &cli.session,
            &cli.source,
            &cli.source_ref,
            &incoming,
        )? {
            Outcome::Reply(body) => {
                stdout
                    .write_all(body.as_bytes())
                    .map_err(|err| err.to_string())?;
                stdout.flush().map_err(|err| err.to_string())?;
            }
            Outcome::Forward => {
                to_child
                    .write_all(incoming.as_bytes())
                    .map_err(|err| err.to_string())?;
                to_child.flush().map_err(|err| err.to_string())?;
                if serde_json::from_str::<serde_json::Value>(&line)
                    .ok()
                    .and_then(|value| value.get("id").cloned())
                    .is_some()
                {
                    loop {
                        let mut response = String::new();
                        from_child
                            .read_line(&mut response)
                            .map_err(|err| err.to_string())?;
                        if response.is_empty() {
                            break;
                        }
                        if memlineage_mcp_proxy::is_response(&response) {
                            let filtered = filter_response(&log, &response)?;
                            stdout
                                .write_all(filtered.as_bytes())
                                .map_err(|err| err.to_string())?;
                            stdout.flush().map_err(|err| err.to_string())?;
                            break;
                        }
                        stdout
                            .write_all(response.as_bytes())
                            .map_err(|err| err.to_string())?;
                        stdout.flush().map_err(|err| err.to_string())?;
                    }
                }
            }
        }
    }
    Ok(())
}
