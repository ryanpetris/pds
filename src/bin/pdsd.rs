use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::exit;

use anyhow::{Context, bail};
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::aot;
use pds::cli::{self, Completion, Shell};
use pds::server::Server;
use pds::{Result, config, keys};

/// Petris Distribution System server daemon
#[derive(Parser)]
// A repeated option keeps its last value.
#[command(name = "pdsd", args_override_self = true)]
struct Cli {
    /// Extra config file merged at highest precedence
    #[arg(long, value_name = "FILE")]
    config: Option<OsString>,
    /// Directory holding id_* host keys
    #[arg(long, value_name = "DIR", default_value_os_t = keys::default_ssh_dir())]
    ssh_dir: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Completion(Completion),
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let _ = error.print();
            exit(if error.kind() == ErrorKind::DisplayHelp {
                0
            } else {
                1
            });
        }
    };
    let result = match cli.command {
        Some(Command::Completion(completion)) => write_completion(completion),
        None => {
            let config = cli.config.filter(|path| !path.is_empty());
            serve(config.as_deref().map(Path::new), &cli.ssh_dir)
        }
    };
    if let Err(error) = result {
        eprintln!("pdsd: {error:#}");
        exit(1);
    }
}

fn write_completion(completion: Completion) -> Result<()> {
    let shell = match completion.shell {
        None => {
            return Ok(cli::write_completion_help(
                Cli::command(),
                &mut cli::Stdout,
            )?);
        }
        Some(Shell::Bash) => aot::Shell::Bash,
        Some(Shell::Zsh) => aot::Shell::Zsh,
        Some(Shell::Fish) => aot::Shell::Fish,
        Some(Shell::Powershell) => aot::Shell::PowerShell,
    };
    aot::generate(shell, &mut Cli::command(), "pdsd", &mut cli::Stdout);
    Ok(())
}

fn serve(config: Option<&Path>, ssh_dir: &Path) -> Result<()> {
    let cfg = config::load_server(config)?;
    let (signers, skipped) = keys::load_signers(ssh_dir)
        .with_context(|| format!("loading host keys from {}", ssh_dir.display()))?;
    for key in skipped {
        eprintln!("pdsd: skipping host key {key}");
    }
    if signers.is_empty() {
        bail!(
            "no usable host keys in {} (need an unencrypted id_* private key)",
            ssh_dir.display()
        );
    }
    eprintln!("pdsd: loaded {} host key(s)", signers.len());
    let server = Server::new(cfg, signers)?;
    tokio::runtime::Runtime::new()?.block_on(server.listen_and_serve())
}
