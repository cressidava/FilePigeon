//! Keeping the rendezvous server key out of plain sight on disk.
//!
//! On Windows it is encrypted with DPAPI for the current user: only this
//! Windows account on this PC can decrypt it, and the config file holds
//! ciphertext. Elsewhere it is stored as-is (the file is readable only by its
//! owner). Either way, a copied key is useless on another device, because the
//! server locks each friend's key to the device it was made for.

use anyhow::Result;

/// Extra input to DPAPI so other programs' DPAPI blobs can't be swapped in.
#[cfg(windows)]
const ENTROPY: &[u8] = b"FilePigeon rendezvous key v1";

/// Encrypt for storage. `None` means "no protection on this platform: store as is".
pub fn protect(plain: &str) -> Result<Option<String>> {
    #[cfg(windows)]
    {
        use base64::Engine;
        let blob = dpapi::protect(plain.as_bytes(), ENTROPY)?;
        Ok(Some(base64::engine::general_purpose::STANDARD.encode(blob)))
    }
    #[cfg(not(windows))]
    {
        let _ = plain;
        Ok(None)
    }
}

pub fn unprotect(stored: &str) -> Result<String> {
    #[cfg(windows)]
    {
        use anyhow::Context;
        use base64::Engine;
        let blob = base64::engine::general_purpose::STANDARD.decode(stored).context("the saved server key is damaged")?;
        let plain = dpapi::unprotect(&blob, ENTROPY)
            .context("the saved server key can't be read by this Windows account; enter it again or pair again")?;
        Ok(String::from_utf8(plain)?)
    }
    #[cfg(not(windows))]
    {
        let _ = stored;
        anyhow::bail!("an encrypted server key from Windows can't be used here; enter it again")
    }
}

#[cfg(windows)]
mod dpapi {
    use anyhow::{bail, Result};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
    }

    /// Copy DPAPI's output and free it.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        unsafe { LocalFree(out.pbData as _) };
        v
    }

    pub fn protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        let (input, extra) = (blob(data), blob(entropy));
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = unsafe {
            CryptProtectData(&input, std::ptr::null(), &extra, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        };
        if ok == 0 {
            bail!("Windows couldn't encrypt the server key ({})", std::io::Error::last_os_error());
        }
        Ok(unsafe { take(out) })
    }

    pub fn unprotect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        let (input, extra) = (blob(data), blob(entropy));
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &extra,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            bail!("{}", std::io::Error::last_os_error());
        }
        Ok(unsafe { take(out) })
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn round_trips_and_hides_the_key() {
        let key = "ab".repeat(64);
        let stored = super::protect(&key).unwrap().unwrap();
        assert!(!stored.contains(&key));
        assert_eq!(super::unprotect(&stored).unwrap(), key);
        assert!(super::unprotect("bm90IGEgYmxvYg==").is_err());
    }
}
