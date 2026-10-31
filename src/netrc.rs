//! Minimal `.netrc` parsing, mirroring httpx's `trust_env`-driven netrc lookup.
//!
//! When enabled, credentials for a request host are taken from the user's
//! `~/.netrc` (or `%USERPROFILE%\_netrc` on Windows) unless explicit auth is set.

use std::collections::HashMap;
use std::path::PathBuf;

/// A parsed `.netrc` file: a map of host -> (login, password), plus an optional
/// `default` entry used when no host matches.
#[derive(Debug, Default, Clone)]
pub(crate) struct Netrc {
    entries: HashMap<String, (String, String)>,
    default: Option<(String, String)>,
}

impl Netrc {
    /// Load from the conventional location, if present and readable.
    pub(crate) fn from_env() -> Option<Netrc> {
        for path in candidate_paths() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                return Some(Netrc::parse(&text));
            }
        }
        None
    }

    /// Parse netrc text.
    pub(crate) fn parse(text: &str) -> Netrc {
        let mut netrc = Netrc::default();
        let tokens: Vec<&str> = text.split_whitespace().collect();
        let mut i = 0;
        let mut current_machine: Option<String> = None;
        let mut login: Option<String> = None;
        let mut password: Option<String> = None;
        let mut is_default = false;

        let flush =
            |machine: &mut Option<String>,
             login: &mut Option<String>,
             password: &mut Option<String>,
             is_default: &mut bool,
             netrc: &mut Netrc| {
                if let (Some(l), Some(p)) = (login.clone(), password.clone()) {
                    if *is_default {
                        netrc.default = Some((l, p));
                    } else if let Some(m) = machine.clone() {
                        netrc.entries.insert(m.to_ascii_lowercase(), (l, p));
                    }
                }
                *machine = None;
                *login = None;
                *password = None;
                *is_default = false;
            };

        while i < tokens.len() {
            match tokens[i] {
                "machine" => {
                    flush(
                        &mut current_machine,
                        &mut login,
                        &mut password,
                        &mut is_default,
                        &mut netrc,
                    );
                    i += 1;
                    if i < tokens.len() {
                        current_machine = Some(tokens[i].to_string());
                    }
                }
                "default" => {
                    flush(
                        &mut current_machine,
                        &mut login,
                        &mut password,
                        &mut is_default,
                        &mut netrc,
                    );
                    is_default = true;
                }
                "login" => {
                    i += 1;
                    if i < tokens.len() {
                        login = Some(tokens[i].to_string());
                    }
                }
                "password" => {
                    i += 1;
                    if i < tokens.len() {
                        password = Some(tokens[i].to_string());
                    }
                }
                "account" | "macdef" => {
                    i += 1; // skip the value token
                }
                _ => {}
            }
            i += 1;
        }
        flush(
            &mut current_machine,
            &mut login,
            &mut password,
            &mut is_default,
            &mut netrc,
        );
        netrc
    }

    /// Look up credentials for a host.
    pub(crate) fn lookup(&self, host: &str) -> Option<(String, String)> {
        self.entries
            .get(&host.to_ascii_lowercase())
            .cloned()
            .or_else(|| self.default.clone())
    }
}

fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(explicit) = std::env::var("NETRC") {
        paths.push(PathBuf::from(explicit));
    }
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".netrc"));
        paths.push(home.join("_netrc"));
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_machines_and_default() {
        let text = "machine example.com login alice password secret\n\
                    default login bob password fallback";
        let netrc = Netrc::parse(text);
        assert_eq!(
            netrc.lookup("example.com"),
            Some(("alice".to_string(), "secret".to_string()))
        );
        assert_eq!(
            netrc.lookup("other.com"),
            Some(("bob".to_string(), "fallback".to_string()))
        );
    }
}
