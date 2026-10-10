//! `filepigeon://` links: clicking an invite link opens FilePigeon with the
//! invite filled in. The link only pre-fills the Join window; nothing happens
//! until the user clicks Join (and the inviter approves).
//!
//! Registered per user (no admin rights) on every start, so it always points
//! at the installed copy; the uninstaller removes it.

/// The only links we act on.
const PREFIX: &str = "filepigeon://join/";

/// An invite link among command-line arguments, if any (Windows passes the
/// clicked link as an argument).
pub fn find_in_args<I: IntoIterator<Item = String>>(args: I) -> Option<String> {
    args.into_iter()
        .find(|a| a.to_ascii_lowercase().starts_with(PREFIX) && a.len() <= 300)
        .map(|a| a.chars().filter(|c| !c.is_control()).collect())
}

#[cfg(windows)]
pub fn register() {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let Ok(exe) = std::env::current_exe() else { return };
    let exe = exe.display().to_string();
    let result = (|| -> std::io::Result<()> {
        let classes = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(r"Software\Classes", winreg::enums::KEY_ALL_ACCESS)?;
        let (root, _) = classes.create_subkey("filepigeon")?;
        root.set_value("", &"URL:FilePigeon invite")?;
        root.set_value("URL Protocol", &"")?;
        let (icon, _) = root.create_subkey("DefaultIcon")?;
        icon.set_value("", &format!("\"{exe}\",0"))?;
        let (cmd, _) = root.create_subkey(r"shell\open\command")?;
        cmd.set_value("", &format!("\"{exe}\" \"%1\""))?;
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("could not register filepigeon:// links: {e}");
    }
}

#[cfg(not(windows))]
pub fn register() {}

#[cfg(test)]
mod tests {
    #[test]
    fn only_join_links_are_taken() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            super::find_in_args(args(&["app.exe", "filepigeon://join/pigeon.example.com/a-b-c-d-e"])).as_deref(),
            Some("filepigeon://join/pigeon.example.com/a-b-c-d-e")
        );
        assert!(super::find_in_args(args(&["app.exe", "--hidden"])).is_none());
        assert!(super::find_in_args(args(&["filepigeon://other/x"])).is_none());
    }
}
