mod actions;
mod app;
mod error;
mod logging;
mod ui;

use anyhow::{Result, bail};
use azkv_core::profiles;
use azkv_core::{Profile, ProxySettings};
use clap::Parser;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind, KeyboardEnhancementFlags,
    PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use ratatui::crossterm::execute;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::actions::{AuthCache, execute as run_action};
use crate::app::{Action, App, Msg};

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
}

fn main() -> Result<()> {
    logging::init_logging();
    let cli = Cli::parse();
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

    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run(profiles, selected, proxy))
}

async fn run(profiles: Vec<Profile>, selected: usize, proxy: Option<ProxySettings>) -> Result<()> {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut app = App::new(profiles, selected);
    app.set_proxy(proxy);
    let mut pending = Some(app.start());
    let mut auths = AuthCache::default();

    let mut terminal = ratatui::init();
    execute!(
        std::io::stdout(),
        EnableBracketedPaste,
        PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES),
    )?;
    spawn_input(tx.clone());
    let result = event_loop(&mut terminal, &mut app, rx, &tx, &mut pending, &mut auths).await;
    let _ = execute!(std::io::stdout(), PopKeyboardEnhancementFlags, DisableBracketedPaste,);
    ratatui::restore();
    result
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
            // Redraw while loading so the spinner animates.
            match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                Ok(msg) => msg,
                Err(_) => continue,
            }
        } else {
            rx.recv().await
        };
        let Some(msg) = msg else {
            break;
        };
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
}
