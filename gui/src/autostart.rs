//! Start at login: one per-user entry under the standard Windows "Run" key that
//! launches FilePigeon straight into the tray. No admin rights involved, and
//! the uninstaller removes the same entry.

/// Value name in the Run key (the installer's uninstall hook deletes this name).
pub const VALUE_NAME: &str = "FilePigeon";

#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// The command Windows runs at sign-in.
fn command_line() -> std::io::Result<String> {
    let exe = std::env::current_exe()?;
    Ok(format!("\"{}\" --hidden", exe.display()))
}

#[cfg(windows)]
mod imp {
    use super::{command_line, VALUE_NAME};
    use std::io;
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    pub fn get(subkey: &str) -> Option<String> {
        RegKey::predef(HKEY_CURRENT_USER).open_subkey(subkey).ok()?.get_value(VALUE_NAME).ok()
    }

    pub fn set(subkey: &str, enabled: bool) -> io::Result<()> {
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(subkey)?;
        if enabled {
            key.set_value(VALUE_NAME, &command_line()?)
        } else {
            match key.delete_value(VALUE_NAME) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                other => other,
            }
        }
    }
}

#[cfg(windows)]
pub fn is_enabled() -> bool {
    imp::get(RUN_KEY).is_some()
}

#[cfg(windows)]
pub fn set(enabled: bool) -> Result<(), String> {
    imp::set(RUN_KEY, enabled).map_err(|e| format!("could not change start-at-login: {e}"))
}

/// If enabled, make sure the entry points at this exact executable (the app may
/// have been updated or moved since it was turned on).
#[cfg(windows)]
pub fn refresh() {
    if let (Some(current), Ok(wanted)) = (imp::get(RUN_KEY), command_line()) {
        if current != wanted {
            let _ = imp::set(RUN_KEY, true);
        }
    }
}

#[cfg(not(windows))]
pub fn is_enabled() -> bool {
    false
}

#[cfg(not(windows))]
pub fn set(_enabled: bool) -> Result<(), String> {
    Err("start at login is only implemented on Windows so far".into())
}

#[cfg(not(windows))]
pub fn refresh() {}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    /// Exercises the real code against a throwaway key, never the real Run key.
    #[test]
    fn enable_disable_roundtrip() {
        let parent = format!(r"Software\FilePigeon-test-{}", std::process::id());
        let key = format!(r"{parent}\Run");
        imp::set(&key, true).unwrap();
        let value = imp::get(&key).expect("value written");
        assert!(value.ends_with("\" --hidden"), "{value}");
        assert!(value.contains(&std::env::current_exe().unwrap().display().to_string()));
        imp::set(&key, false).unwrap();
        assert!(imp::get(&key).is_none());
        imp::set(&key, false).unwrap(); // disabling twice is fine
        RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&parent).unwrap();
    }
}
