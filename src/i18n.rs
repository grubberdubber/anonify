//! Language detection and selection for anonify's CLI output.
//!
//! Detection order (first match wins):
//!   1. `--lang <code>` CLI flag (explicit user override, highest priority)
//!   2. `ANONIFY_LANG` environment variable (persistent user override)
//!   3. POSIX locale env vars: `LC_ALL`, `LC_MESSAGES`, `LANG` (OS default)
//!   4. Fallback: English
//!
//! English is the primary language the tool is built around; Spanish is
//! offered as a translation. Add more `Lang` variants here as translations
//! are added — nothing else needs to change structurally.

use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Es,
}

impl Lang {
    /// Resolve the active language from an optional explicit CLI flag and
    /// the process environment. `cli_flag` should be `Some("es")`,
    /// `Some("en")`, etc. when the user passed `--lang`, or `None`.
    pub fn resolve(cli_flag: Option<&str>) -> Self {
        if let Some(code) = cli_flag {
            return Self::from_code(code).unwrap_or(Lang::En);
        }

        if let Ok(code) = env::var("ANONIFY_LANG") {
            if let Some(lang) = Self::from_code(&code) {
                return lang;
            }
        }

        for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Ok(val) = env::var(var) {
                if let Some(lang) = Self::from_locale_string(&val) {
                    return lang;
                }
            }
        }

        Lang::En
    }

    fn from_code(code: &str) -> Option<Self> {
        match code.to_lowercase().as_str() {
            "es" | "es-es" | "es-cl" | "spanish" => Some(Lang::Es),
            "en" | "en-us" | "en-gb" | "english" => Some(Lang::En),
            _ => None,
        }
    }

    /// Parses POSIX-style locale strings like "es_CL.UTF-8" or "en_US.UTF-8".
    fn from_locale_string(locale: &str) -> Option<Self> {
        let primary = locale.split(['_', '.']).next()?;
        Self::from_code(primary)
    }
}

/// Picks the right static string for the active language. Used as:
/// `tr(lang, "English text", "Texto en español")`
pub fn tr(lang: Lang, en: &'static str, es: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::Es => es,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_posix_locale() {
        assert_eq!(Lang::from_locale_string("es_CL.UTF-8"), Some(Lang::Es));
        assert_eq!(Lang::from_locale_string("en_US.UTF-8"), Some(Lang::En));
        assert_eq!(Lang::from_locale_string("C"), None);
    }

    #[test]
    fn cli_flag_wins_over_everything() {
        assert_eq!(Lang::resolve(Some("es")), Lang::Es);
    }
}
