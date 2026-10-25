use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::error::ErrorKind;
use clap::{ArgMatches, Args, CommandFactory, Parser, Subcommand, ValueEnum, ValueHint};
use clap_complete::engine::{ArgValueCompleter, CompletionCandidate};
use clap_complete::env::{Bash, CompleteEnv, Fish, Powershell, Shells, Zsh};

use crate::client::{self, Client, DirEntry};
use crate::{Result, config};

/// Environment variable that switches `pds` into answering a completion request.
const COMPLETE_VAR: &str = "PDS_COMPLETE";
const SHELLS: Shells<'static> = Shells(&[&Bash, &Zsh, &Fish, &Powershell]);

/// Petris Distribution System client
///
/// Paths are bucket-first: the first segment names a bucket (or the .pds
/// namespace). Authenticity comes from the SSH transport. The client pins the
/// server's host key and authenticates by public key.
#[derive(Parser)]
// A repeated option keeps its last value.
#[command(name = "pds", args_override_self = true)]
struct Cli {
    /// Config file, merged at highest precedence
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<OsString>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Copy a file from the server (default: stdout)
    Pull {
        #[arg(add = ArgValueCompleter::new(|word: &OsStr| remote(word, |_| true, complete_path)))]
        path: String,
        /// Write to FILE instead of stdout
        #[arg(short, long, value_name = "FILE", value_hint = ValueHint::FilePath)]
        output: Option<OsString>,
    },
    /// List a directory (default: root)
    Ls {
        #[arg(add = ArgValueCompleter::new(|word: &OsStr| remote(word, |_| true, complete_path)))]
        path: Option<String>,
    },
    /// Upload data to a bucket (default: stdin)
    Push {
        #[arg(add = ArgValueCompleter::new(|word: &OsStr| remote(word, |_| true, complete_bucket)))]
        bucket: String,
        #[arg(value_name = "FILE|-")]
        file: Option<PathBuf>,
    },
    /// Print a bucket's .meta document
    Meta {
        #[arg(add = ArgValueCompleter::new(|word: &OsStr| remote(word, |_| true, complete_bucket)))]
        bucket: String,
    },
    /// Run a script from .pds/exec
    // One positional holds the name and the script's arguments, so every word
    // after the name, including -h, --config and --, reaches the script.
    #[command(
        disable_help_flag = true,
        override_usage = "pds exec [OPTIONS] <NAME> [ARGS]..."
    )]
    Exec {
        #[arg(
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "NAME",
            add = ArgValueCompleter::new(|word: &OsStr| remote(
                word,
                |typed| typed.get_many::<OsString>("argv").is_none(),
                complete_exec,
            )),
        )]
        argv: Vec<OsString>,
    },
    /// Print the ordered server endpoints (SSH host:port, or HTTP URLs)
    Endpoint {
        /// Print the SSH endpoints (host:port; default)
        #[arg(long, conflicts_with = "http")]
        ssh: bool,
        /// Print the read-only HTTP URLs
        #[arg(long)]
        http: bool,
    },
    Completion(Completion),
}

/// Generate a shell completion script
#[derive(Args)]
pub struct Completion {
    pub shell: Option<Shell>,
    #[arg(long, hide = true)]
    pub no_descriptions: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

/// Runs `pds` and returns its exit status.
pub fn run() -> i32 {
    CompleteEnv::with_factory(Cli::command)
        .var(COMPLETE_VAR)
        .shells(SHELLS)
        .complete();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let _ = error.print();
            return if error.kind() == ErrorKind::DisplayHelp {
                0
            } else {
                1
            };
        }
    };
    let Some(command) = cli.command else {
        let _ = Cli::command().write_help(&mut io::stderr());
        return 2;
    };
    match execute(command, nonempty(cli.config.as_ref())).and_then(|code| {
        Stdout.flush()?;
        Ok(code)
    }) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("pds: {error:#}");
            1
        }
    }
}

/// An empty path means none was given.
fn nonempty(path: Option<&OsString>) -> Option<&Path> {
    path.filter(|path| !path.is_empty()).map(Path::new)
}

fn execute(command: Command, config: Option<&Path>) -> Result<i32> {
    match command {
        Command::Pull { path, output } => with_client(config, |client| {
            match nonempty(output.as_ref()) {
                // The file is created before the remote open, so a failed pull
                // leaves it empty.
                Some(output) => client.pull(
                    &path,
                    &mut File::create(output)
                        .with_context(|| format!("create {}", output.display()))?,
                ),
                None => client.pull(&path, &mut Stdout),
            }
        })?,
        Command::Ls { path } => with_client(config, |client| {
            for entry in client.read_dir(path.as_deref().unwrap_or("/"))? {
                writeln!(
                    Stdout,
                    "{}{}",
                    entry.name,
                    if entry.is_dir { "/" } else { "" }
                )?;
            }
            Ok(())
        })?,
        Command::Push { bucket, file } => with_client(config, |client| match file {
            Some(file) if file != Path::new("-") => client.push(
                &bucket,
                &mut File::open(&file).with_context(|| format!("open {}", file.display()))?,
            ),
            _ => client.push(&bucket, &mut io::stdin()),
        })?,
        Command::Meta { bucket } => {
            with_client(config, |client| client.meta(&bucket, &mut Stdout))?
        }
        Command::Exec { argv } => {
            let name = argv[0].to_str().context("script name is not valid UTF-8")?;
            return with_client(config, |client| client.exec(name, &argv[1..]));
        }
        Command::Endpoint { http, .. } => {
            // endpoint only prints addresses, so it never dials and skips the
            // validation of fields it does not print.
            let cfg = config::load_client_unvalidated(config)?;
            let endpoints = if http {
                client::resolve_http_urls(&cfg)?
            } else {
                client::resolve_endpoints(&cfg)?
            };
            for endpoint in endpoints {
                writeln!(Stdout, "{endpoint}")?;
            }
        }
        Command::Completion(Completion { shell: None, .. }) => {
            write_completion_help(Cli::command(), &mut Stdout)?
        }
        Command::Completion(Completion {
            shell: Some(shell), ..
        }) => write_registration(shell, &mut Stdout)?,
    }
    Ok(0)
}

fn with_client<T>(config: Option<&Path>, run: impl FnOnce(&Client) -> Result<T>) -> Result<T> {
    let client = Client::dial(&config::load_client(config)?)?;
    let result = run(&client);
    let _ = client.close();
    result
}

/// Writes the help of the completion subcommand of `cmd`, shown when no shell
/// is given.
pub fn write_completion_help(mut cmd: clap::Command, out: &mut impl Write) -> io::Result<()> {
    cmd.build();
    let completion = cmd
        .find_subcommand_mut("completion")
        .expect("command has a completion subcommand");
    completion.write_help(out)
}

fn write_registration(shell: Shell, out: &mut dyn Write) -> io::Result<()> {
    let name = shell.to_possible_value().expect("no skipped shells");
    let completer = SHELLS
        .completer(name.get_name())
        .expect("every shell has a completer");
    // The script runs the bare name so it finds pds through PATH, not the path
    // of the binary that generated it.
    completer.write_registration(COMPLETE_VAR, "pds", "pds", "pds", out)?;
    if let Shell::Zsh = shell {
        // Installed in $fpath as _pds, the script runs on the first TAB and
        // only registers the completer. This line answers that TAB too.
        writeln!(
            out,
            r#"if [[ ${{funcstack[1]}} == _pds ]]; then _clap_dynamic_completer_pds "$@"; fi"#
        )?;
    }
    Ok(())
}

/// Standard output that ends the process by SIGPIPE once the reader goes away,
/// as programs with the default signal action do, instead of reporting an error.
pub struct Stdout;

impl Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stdout().write(buf).inspect_err(die_on_broken_pipe)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush().inspect_err(die_on_broken_pipe)
    }
}

fn die_on_broken_pipe(error: &io::Error) {
    if error.kind() == io::ErrorKind::BrokenPipe {
        // SAFETY: both calls are async-signal-safe and only change this
        // process's handling of SIGPIPE before raising it.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            libc::raise(libc::SIGPIPE);
        }
    }
}

type ReadDir<'a> = &'a dyn Fn(&str) -> Result<Vec<DirEntry>>;

/// Completes `word` from a live listing. The engine passes only the word under
/// the cursor, so the configuration and the words already typed come from
/// re-parsing the command line. `wanted` sees those typed words. Any failure
/// yields no candidates.
fn remote(
    word: &OsStr,
    wanted: fn(&ArgMatches) -> bool,
    complete: fn(ReadDir, &str) -> Result<Vec<String>>,
) -> Vec<CompletionCandidate> {
    let words = || {
        let word = word.to_str()?;
        let index = env::var("_CLAP_COMPLETE_INDEX")
            .ok()
            .and_then(|i| i.parse().ok());
        let typed = typed_matches(typed_words(env::args_os(), index))?;
        if !wanted(&typed) {
            return None;
        }
        let cfg = config::load_client(nonempty(typed.get_one::<OsString>("config"))).ok()?;
        let client = Client::dial(&cfg).ok()?;
        let words = complete(&|path| client.read_dir(path), word);
        let _ = client.close();
        words.ok()
    };
    words()
        .unwrap_or_default()
        .into_iter()
        .map(CompletionCandidate::new)
        .collect()
}

/// Returns the words of a completion request before the cursor, starting with
/// the program name. `args` is this process's argv, which carries the request
/// after `--`. `index` is the cursor position for shells that report one;
/// otherwise the last word is under the cursor.
fn typed_words(args: impl Iterator<Item = OsString>, index: Option<usize>) -> Vec<OsString> {
    let words: Vec<_> = args.skip_while(|arg| arg != "--").skip(1).collect();
    let index = index.unwrap_or(words.len().saturating_sub(1));
    words.into_iter().take(index).collect()
}

/// Parses incomplete command words and returns the subcommand's matches.
fn typed_matches(words: Vec<OsString>) -> Option<ArgMatches> {
    let mut matches = Cli::command()
        .ignore_errors(true)
        .try_get_matches_from(words)
        .ok()?;
    matches.remove_subcommand().map(|(_, matches)| matches)
}

/// Bucket names are the visible top-level directories.
fn complete_bucket(read_dir: ReadDir, word: &str) -> Result<Vec<String>> {
    Ok(read_dir("/")?
        .into_iter()
        .filter(|entry| {
            entry.is_dir && !entry.name.starts_with('.') && entry.name.starts_with(word)
        })
        .map(|entry| entry.name)
        .collect())
}

/// Path candidates are whole words under the directory part of `word`.
/// Directories end in a slash so completion can descend into them.
fn complete_path(read_dir: ReadDir, word: &str) -> Result<Vec<String>> {
    let (parent, prefix) = match word.rfind('/') {
        Some(slash) => word.split_at(slash + 1),
        None => ("", word),
    };
    Ok(read_dir(parent)?
        .into_iter()
        .filter(|entry| entry.name.starts_with(prefix))
        .map(|entry| {
            format!(
                "{parent}{}{}",
                entry.name,
                if entry.is_dir { "/" } else { "" }
            )
        })
        .collect())
}

/// Script names are the visible files in .pds/exec.
fn complete_exec(read_dir: ReadDir, word: &str) -> Result<Vec<String>> {
    Ok(
        read_dir(&format!("/{}/{}", config::NAME_PDS, config::NAME_EXEC))?
            .into_iter()
            .filter(|entry| {
                !entry.is_dir && !entry.name.starts_with('.') && entry.name.starts_with(word)
            })
            .map(|entry| entry.name)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use anyhow::anyhow;

    use super::*;

    fn parse(args: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("pds").chain(args.iter().copied()))
    }

    fn exec_argv(args: &[&str]) -> (Option<OsString>, Vec<OsString>) {
        let cli = parse(args).unwrap();
        match cli.command {
            Some(Command::Exec { argv }) => (cli.config, argv),
            _ => panic!("{args:?} did not parse as exec"),
        }
    }

    fn os(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn exec_passes_arguments_through() {
        let (config, argv) = exec_argv(&["exec", "s.sh", "--config", "z", "-h", "--", "-", ""]);
        assert_eq!(config, None);
        assert_eq!(argv, os(&["s.sh", "--config", "z", "-h", "--", "-", ""]));

        assert_eq!(exec_argv(&["exec", "-h"]).1, os(&["-h"]));
        assert_eq!(
            exec_argv(&["exec", "--", "s.sh", "a"]).1,
            os(&["s.sh", "a"])
        );
    }

    #[test]
    fn exec_honors_config_before_name() {
        for args in [
            &["--config", "f", "exec", "s.sh", "a"][..],
            &["exec", "-c", "f", "s.sh", "a"],
        ] {
            let (config, argv) = exec_argv(args);
            assert_eq!(config, Some(OsString::from("f")), "{args:?}");
            assert_eq!(argv, os(&["s.sh", "a"]), "{args:?}");
        }
    }

    #[test]
    fn config_forms() {
        for args in [
            &["--config", "f", "ls"][..],
            &["--config=f", "ls"],
            &["-cf", "ls"],
            &["-c", "f", "ls"],
            &["ls", "-c", "f"],
        ] {
            assert_eq!(
                parse(args).unwrap().config,
                Some(OsString::from("f")),
                "{args:?}"
            );
        }
        assert_eq!(
            nonempty(parse(&["--config", "", "ls"]).unwrap().config.as_ref()),
            None
        );
        assert_eq!(
            parse(&["--config", "", "-c", "f", "ls"]).unwrap().config,
            Some("f".into())
        );
        assert!(parse(&["endpoint", "--http", "--http"]).is_ok());
    }

    #[test]
    fn positionals_after_separator() {
        match parse(&["pull", "--", "scripts/-"]).unwrap().command {
            Some(Command::Pull { path, output: None }) => assert_eq!(path, "scripts/-"),
            _ => panic!("pull did not parse"),
        }
        match parse(&["push", "--", "raw", "-upload"]).unwrap().command {
            Some(Command::Push { bucket, file }) => {
                assert_eq!(bucket, "raw");
                assert_eq!(file, Some(PathBuf::from("-upload")));
            }
            _ => panic!("push did not parse"),
        }
        match parse(&["push", "raw", "-"]).unwrap().command {
            Some(Command::Push { file, .. }) => assert_eq!(file, Some(PathBuf::from("-"))),
            _ => panic!("push did not parse"),
        }
    }

    #[test]
    fn parse_outcomes() {
        assert!(parse(&[]).unwrap().command.is_none());
        assert!(parse(&["-c", "f"]).unwrap().command.is_none());
        for args in [
            &["--help"][..],
            &["-h"],
            &["help"],
            &["help", "exec"],
            &["ls", "--help"],
        ] {
            assert_eq!(
                parse(args).err().map(|e| e.kind()),
                Some(ErrorKind::DisplayHelp),
                "{args:?}"
            );
        }
        for args in [
            &["exec"][..],
            &["nope"],
            &["ls", "a", "b"],
            &["meta"],
            &["ls", "--nope"],
            &["endpoint", "--ssh", "--http"],
            &["completion", "elvish"],
        ] {
            let kind = parse(args).err().map(|e| e.kind());
            assert!(
                kind.is_some_and(|kind| kind != ErrorKind::DisplayHelp),
                "{args:?}"
            );
        }
        assert!(parse(&["endpoint", "--ssh"]).is_ok());
        match parse(&["completion"]).unwrap().command {
            Some(Command::Completion(Completion { shell: None, .. })) => {}
            _ => panic!("completion did not parse"),
        }
        assert!(parse(&["completion", "zsh", "--no-descriptions"]).is_ok());
    }

    #[test]
    fn completion_help_and_registration() {
        let mut help = Vec::new();
        write_completion_help(Cli::command(), &mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(help.contains("pds completion"), "{help}");
        assert!(
            help.contains("powershell") && !help.contains("elvish"),
            "{help}"
        );

        for shell in Shell::value_variants() {
            let mut script = Vec::new();
            write_registration(*shell, &mut script).unwrap();
            let script = String::from_utf8(script).unwrap();
            assert!(script.contains(COMPLETE_VAR), "{script}");
        }
        let mut zsh = Vec::new();
        write_registration(Shell::Zsh, &mut zsh).unwrap();
        assert!(
            String::from_utf8(zsh)
                .unwrap()
                .ends_with("_clap_dynamic_completer_pds \"$@\"; fi\n")
        );
    }

    #[test]
    fn completion_context() {
        let words = |line: &str, index| typed_words(line.split(' ').map(OsString::from), index);
        assert_eq!(
            words("pds -- pds ls -c f scr", None),
            os(&["pds", "ls", "-c", "f"])
        );
        assert_eq!(words("pds -- pds ls scr -c f", Some(2)), os(&["pds", "ls"]));

        let config = |line: &str| {
            typed_matches(words(line, None))
                .and_then(|typed| typed.get_one::<OsString>("config").cloned())
        };
        assert_eq!(config("pds -- pds -c f ls x"), Some(OsString::from("f")));
        assert_eq!(
            config("pds -- pds --config=h pull x"),
            Some(OsString::from("h"))
        );
        assert_eq!(config("pds -- pds ls -c g x"), Some(OsString::from("g")));
        assert_eq!(config("pds -- pds -c f exec x"), Some(OsString::from("f")));
        assert_eq!(config("pds -- pds ls x"), None);

        let typed_argv = |line: &str| {
            typed_matches(words(line, None))
                .unwrap()
                .get_many::<OsString>("argv")
                .map_or(0, |argv| argv.len())
        };
        assert_eq!(typed_argv("pds -- pds exec x"), 0);
        assert_eq!(typed_argv("pds -- pds -c f exec x"), 0);
        assert_eq!(typed_argv("pds -- pds exec -- x"), 0);
        assert_eq!(typed_argv("pds -- pds exec s.sh x"), 1);
        assert_eq!(typed_argv("pds -- pds exec s.sh -c f x"), 3);
    }

    fn listing(dirs: &[(&str, &[(&str, bool)])]) -> impl Fn(&str) -> Result<Vec<DirEntry>> {
        let map: HashMap<String, Vec<DirEntry>> = dirs
            .iter()
            .map(|(path, entries)| {
                let entries = entries
                    .iter()
                    .map(|&(name, is_dir)| DirEntry {
                        name: name.into(),
                        is_dir,
                    })
                    .collect();
                (path.to_string(), entries)
            })
            .collect();
        // The client resolves remote paths against the root.
        move |path| {
            let path = format!("/{}", path.trim_matches('/'));
            map.get(&path)
                .cloned()
                .ok_or_else(|| anyhow!("{path}: not found"))
        }
    }

    #[test]
    fn buckets() {
        let read_dir = listing(&[(
            "/",
            &[
                ("scripts", true),
                ("metrics", true),
                (".pds", true),
                ("README", false),
            ],
        )]);
        assert_eq!(
            complete_bucket(&read_dir, "").unwrap(),
            ["scripts", "metrics"]
        );
        assert_eq!(complete_bucket(&read_dir, "scr").unwrap(), ["scripts"]);
        assert!(complete_bucket(&listing(&[]), "").is_err());
    }

    #[test]
    fn paths() {
        let read_dir = listing(&[
            (
                "/",
                &[("scripts", true), ("metrics", true), ("top.txt", false)],
            ),
            (
                "/scripts",
                &[("sub", true), ("hello.sh", false), ("bye.sh", false)],
            ),
        ]);
        assert_eq!(
            complete_path(&read_dir, "").unwrap(),
            ["scripts/", "metrics/", "top.txt"]
        );
        assert_eq!(
            complete_path(&read_dir, "scripts/h").unwrap(),
            ["scripts/hello.sh"]
        );
        assert_eq!(
            complete_path(&read_dir, "/scripts/s").unwrap(),
            ["/scripts/sub/"]
        );
    }

    #[test]
    fn exec_scripts() {
        let read_dir = listing(&[(
            "/.pds/exec",
            &[
                ("deploy.sh", false),
                ("backup.sh", false),
                (".meta", false),
                ("nested", true),
            ],
        )]);
        assert_eq!(
            complete_exec(&read_dir, "").unwrap(),
            ["deploy.sh", "backup.sh"]
        );
        assert_eq!(complete_exec(&read_dir, "dep").unwrap(), ["deploy.sh"]);
    }
}
