mod actions;
mod app;
mod error;
mod logging;
mod ui;

use crate::actions::{AuthCache, execute as run_action};
use crate::app::{Action, App, Msg};
use anyhow::{Result, bail};
use azkv_core::{
    profiles, {Profile, ProxySettings},
};
use clap::{Parser, Subcommand};
use libc::{SIGTSTP, raise};
use ratatui::{
    crossterm::{
        event::{
            self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
            KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
        },
        execute,
    },
    {DefaultTerminal, init, restore},
};
use std::io::stdout;
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    time::timeout,
};
use tracing::info;

#[derive(Parser)]
#[command(name = "azkv", about = "Azure Key Vault TUI: browse, reveal and copy secrets")]
struct Cli {
    /// Azure CLI profile: name under ~/.azure, or a config dir path
    #[arg(long, env = "AZKV_PROFILE")]
    profile: Option<String>,

    /// HTTP(S)/SOCKS proxy for Key Vault and Azure management calls (default: proxy env)
    #[arg(long, env = "AZKV_PROXY")]
    proxy: Option<String>,

    /// Hosts that bypass --proxy (default: NO_PROXY env)
    #[arg(long, env = "AZKV_NO_PROXY")]
    no_proxy: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Info,
    Version,
}

fn main() -> Result<()> {
    logging::init_logging();
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Version) => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        },
        Some(Command::Info) => {
            let log =
                logging::log_path().map(|path| path.display().to_string()).unwrap_or_else(|| "unavailable".into());
            println!("Version:           {}", env!("CARGO_PKG_VERSION"));
            println!("Logs:              {log}");
            return Ok(());
        },
        None => {},
    }
    let mut profiles = profiles::discover().unwrap_or_default();
    let selected = match &cli.profile {
        Some(spec) => {
            let profile = profiles::resolve(Some(spec))?;
            match profiles.iter().position(|known| known.dir == profile.dir) {
                Some(index) => index,
                None => {
                    profiles.push(profile);
                    profiles.len() - 1
                },
            }
        },
        None => {
            let active = profiles::active()?;
            profiles.iter().position(|known| known.dir == active.dir).unwrap_or(0)
        },
    };
    if profiles.is_empty() {
        bail!("no Azure CLI profiles found; run `az login` first");
    }
    let proxy = ProxySettings::new(cli.proxy.as_deref(), cli.no_proxy.as_deref())?;
    match &proxy {
        Some(proxy) => {
            info!("proxy {} (no_proxy: {})", proxy.display_url(), proxy.no_proxy().unwrap_or("none"))
        },
        None => info!("no proxy: direct transport (set --proxy or use P)"),
    }

    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run(profiles, selected, proxy))
}

async fn run(profiles: Vec<Profile>, selected: usize, proxy: Option<ProxySettings>) -> Result<()> {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut app = App::new(profiles, selected);
    app.set_proxy(proxy);
    let mut pending = app.start();
    let mut auths = AuthCache::default();

    let mut terminal = enter_terminal()?;
    spawn_input(tx.clone());
    let result = event_loop(&mut terminal, &mut app, rx, &tx, &mut pending, &mut auths).await;
    leave_terminal();
    result
}

fn enter_terminal() -> Result<DefaultTerminal> {
    let terminal = init();
    execute!(
        stdout(),
        EnableBracketedPaste,
        PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES),
    )?;
    Ok(terminal)
}

fn leave_terminal() {
    let _ = execute!(stdout(), PopKeyboardEnhancementFlags, DisableBracketedPaste);
    restore();
}

fn is_suspend_key(key: &KeyEvent) -> bool {
    key.code == KeyCode::Char('z') && key.modifiers.contains(KeyModifiers::CONTROL)
}

fn suspend() {
    unsafe { raise(SIGTSTP) };
}

async fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    mut rx: UnboundedReceiver<Msg>,
    tx: &UnboundedSender<Msg>,
    pending: &mut Option<Action>,
    auths: &mut AuthCache,
) -> Result<()> {
    loop {
        terminal.draw(|frame| ui::draw(frame, app))?;
        if let Some(action) = pending.take() {
            if run_action(action, tx, auths, app.proxy()) {
                break;
            }
            continue;
        }
        let msg = if app.loading {
            match timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                Ok(msg) => msg,
                Err(_) => continue,
            }
        } else {
            rx.recv().await
        };
        let Some(msg) = msg else {
            break;
        };
        if let Msg::Key(key) = &msg
            && is_suspend_key(key)
        {
            leave_terminal();
            suspend();
            *terminal = enter_terminal()?;
            continue;
        }
        *pending = app.handle(msg);
    }

    Ok(())
}
fn spawn_input(tx: UnboundedSender<Msg>) {
    std::thread::spawn(move || {
        while let Ok(event) = event::read() {
            let sent = match event {
                Event::Key(key) if key.kind != KeyEventKind::Release => tx.send(Msg::Key(key)),
                Event::Paste(text) => tx.send(Msg::Paste(text)),
                Event::Resize(..) => tx.send(Msg::Resize),
                _ => Ok(()),
            };
            if sent.is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_flags_are_parsed() {
        let cli = Cli::try_parse_from(["azkv", "--proxy", "http://127.0.0.1:8080", "--no-proxy", "localhost"]).unwrap();
        assert_eq!(cli.proxy.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(cli.no_proxy.as_deref(), Some("localhost"));
    }

    #[test]
    fn info_and_version_subcommands_are_parsed() {
        assert!(matches!(Cli::try_parse_from(["azkv", "info"]).unwrap().command, Some(Command::Info)));
        assert!(matches!(Cli::try_parse_from(["azkv", "version"]).unwrap().command, Some(Command::Version)));
        assert!(Cli::try_parse_from(["azkv"]).unwrap().command.is_none());
    }

    #[test]
    fn only_ctrl_z_suspends() {
        assert!(is_suspend_key(&KeyEvent::new(KeyCode::Char('z'), KeyModifiers::CONTROL)));
        assert!(!is_suspend_key(&KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE)));
    }
}
