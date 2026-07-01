//! Plain TOML config at `$XDG_CONFIG_HOME/um/config.toml` (fallback
//! `~/.config/um/config.toml`). Holds only non-sensitive data: the relay
//! `server_addr` and the `last_identity_pub` (to locate the store file). The
//! passphrase is never stored; the store file holds all secrets, encrypted.
//!
//! Read at startup (sync, before iced launch — small file). Written on Connect
//! (persist chosen server) and on Setup (persist `last_identity_pub`).

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The default relay address, matching `um_server`'s default
/// (`UM_SERVER_ADDR`, `crates/server/src/main.rs`).
pub const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:7000";

/// On-disk config shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Last-used relay address (persisted on Connect).
    #[serde(default = "default_server_addr")]
    pub server_addr: String,
    /// Hex of the last-unlocked identity pub, used to locate the store file.
    /// Empty on first run → Setup view.
    #[serde(default)]
    pub last_identity_pub: String,
}

fn default_server_addr() -> String {
    DEFAULT_SERVER_ADDR.to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_addr: default_server_addr(),
            last_identity_pub: String::new(),
        }
    }
}

impl Config {
    /// Parse the `server_addr` string into a `SocketAddr`, falling back to the
    /// default on a bad string.
    pub fn server_socket_addr(&self) -> SocketAddr {
        self.server_addr.parse().unwrap_or_else(|_| {
            DEFAULT_SERVER_ADDR
                .parse()
                .expect("default server addr is a valid SocketAddr")
        })
    }

    /// Render to a TOML string.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string(self).map_err(ConfigError::Serialize)
    }

    /// Parse from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(ConfigError::Deserialize)
    }
}

/// Config load/save errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config serialize: {0}")]
    Serialize(toml::ser::Error),
    #[error("config deserialize: {0}")]
    Deserialize(toml::de::Error),
    #[error("config io: {0}")]
    Io(#[from] std::io::Error),
}

/// Resolve the config directory (`$XDG_CONFIG_HOME/um` or `~/.config/um`).
pub fn config_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("um"))
}

/// Resolve the data directory for store files
/// (`$XDG_DATA_HOME/um` or `~/.local/share/um`).
pub fn data_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("um"))
}

/// Path to the config file.
pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("config.toml"))
}

/// Store file path for a given identity pub (hex). Keyed by identity pub so
/// multiple identities coexist.
pub fn store_path(identity_pub_hex: &str) -> Option<PathBuf> {
    data_dir().map(|d| d.join(format!("{identity_pub_hex}.db")))
}

/// Load the config from the default path, or `Config::default()` if the file
/// is absent (first run). A corrupt file is also treated as default rather
/// than fatal — the user can re-pick a server.
pub fn load() -> Config {
    let Some(path) = config_path() else {
        return Config::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(s) => Config::from_toml(&s).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

/// Save the config to the default path, creating the directory first.
pub fn save(cfg: &Config) -> Result<(), ConfigError> {
    let Some(path) = config_path() else {
        return Err(ConfigError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no config directory (XDG unavailable)",
        )));
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, cfg.to_toml()?)?;
    Ok(())
}

/// True if a store file exists for `identity_pub_hex` (cheap `Path::exists`).
/// Used by the app to decide Setup vs Login on startup without a bridge round
/// trip.
pub fn store_exists(identity_pub_hex: &str) -> bool {
    store_path(identity_pub_hex).is_some_and(|p| p.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trips_through_toml() {
        let cfg = Config {
            server_addr: "1.2.3.4:7000".to_string(),
            last_identity_pub: "ab".to_string(),
        };
        let s = cfg.to_toml().unwrap();
        let back = Config::from_toml(&s).unwrap();
        assert_eq!(back.server_addr, "1.2.3.4:7000");
        assert_eq!(back.last_identity_pub, "ab");
    }

    #[test]
    fn default_config_uses_default_server() {
        let cfg = Config::default();
        assert_eq!(cfg.server_addr, DEFAULT_SERVER_ADDR);
        assert_eq!(
            cfg.server_socket_addr(),
            DEFAULT_SERVER_ADDR.parse().unwrap()
        );
        assert!(cfg.last_identity_pub.is_empty());
    }

    #[test]
    fn bad_server_addr_falls_back_to_default() {
        let cfg = Config {
            server_addr: "not an addr".to_string(),
            last_identity_pub: String::new(),
        };
        assert_eq!(
            cfg.server_socket_addr(),
            DEFAULT_SERVER_ADDR.parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn from_toml_with_missing_fields_uses_defaults() {
        // Empty TOML → all defaults (serde `default` attrs).
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.server_addr, DEFAULT_SERVER_ADDR);
        assert!(cfg.last_identity_pub.is_empty());
    }

    #[test]
    fn store_path_keyed_by_identity_hex() {
        let p = store_path("deadbeef").unwrap();
        assert!(p.to_string_lossy().ends_with("deadbeef.db"));
    }
}
