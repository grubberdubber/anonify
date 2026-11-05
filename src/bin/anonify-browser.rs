//! Portable entry point: a hardened, throwaway browser profile on any OS.
//!
//! Unlike the `anonify` binary, this one does not touch the system at all: no
//! root, no firewall, no sysctl, no MAC. That is why it builds and runs on
//! Windows and macOS, where the Linux engine does not exist.
use anonify::browser;
use anonify::i18n::Lang;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "anonify-browser",
    version,
    about = "Open Firefox/LibreWolf with a throwaway, leak-hardened profile (no root)"
)]
struct Cli {
    /// Force a language instead of auto-detecting from the OS locale (en, es)
    #[arg(long, global = true)]
    lang: Option<String>,

    /// Page to open (http/https only); omit for a blank start
    url: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let lang = Lang::resolve(cli.lang.as_deref());
    let code = browser::run(cli.url.as_deref(), lang)?;
    std::process::exit(code);
}
