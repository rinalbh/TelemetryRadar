//! Current-user physical Root store operations, excluding machine/policy roots.
use super::{TrustInsert, TrustStore};
use crate::Result;

pub(super) struct WindowsTrust;

fn insert_new_certificate(
    store: &mut schannel::cert_store::CertStore,
    der: &[u8],
) -> Result<TrustInsert> {
    let certificate = schannel::cert_context::CertContext::new(der)?;
    match store.add_cert(&certificate, schannel::cert_store::CertAdd::New) {
        Ok(_) => Ok(TrustInsert::Added),
        Err(error)
            if error.raw_os_error().is_some_and(|code| {
                code as u32 == windows_sys::Win32::Foundation::CRYPT_E_EXISTS as u32
            }) =>
        {
            Ok(TrustInsert::AlreadyPresent)
        }
        Err(error) => Err(error.into()),
    }
}
fn user_root_store() -> Result<schannel::cert_store::CertStore> {
    use schannel::RawPointer;
    use windows_sys::Win32::Security::Cryptography::{
        CERT_STORE_PROV_SYSTEM_REGISTRY_W, CERT_SYSTEM_STORE_CURRENT_USER, CertOpenStore,
    };
    let root: Vec<u16> = "Root\0".encode_utf16().collect();
    // The registry provider opens only the user's physical Root store, excluding
    // inherited machine/group-policy stores. schannel handles all other operations.
    // SAFETY: root is null-terminated and lives for the call; the returned store
    // handle is owned exactly once by the schannel RAII wrapper.
    let handle = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_REGISTRY_W,
            0,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER,
            root.as_ptr().cast(),
        )
    };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { schannel::cert_store::CertStore::from_ptr(handle) })
}
impl TrustStore for WindowsTrust {
    fn contains(&self, der: &[u8]) -> Result<bool> {
        let store = user_root_store()?;
        Ok(store.certs().any(|certificate| certificate.to_der() == der))
    }
    fn add_new(&self, der: &[u8]) -> Result<TrustInsert> {
        let mut store = user_root_store()?;
        insert_new_certificate(&mut store, der)
    }
    fn remove_exact(&self, der: &[u8]) -> Result<()> {
        let store = user_root_store()?;
        let matches: Vec<_> = store
            .certs()
            .filter(|certificate| certificate.to_der() == der)
            .collect();
        for certificate in matches {
            certificate.delete()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_duplicate_import_does_not_replace_or_claim_existing_certificate() {
        // Exercise the real Crypt32 result code without installing system trust
        // or displaying a certificate dialog.
        let mut store = schannel::cert_store::Memory::new().unwrap().into_store();
        let der = pem::parse(include_str!("../../../tests/fixtures/capture-ca.pem"))
            .unwrap()
            .into_contents();
        assert!(matches!(
            insert_new_certificate(&mut store, &der).unwrap(),
            TrustInsert::Added
        ));
        assert!(matches!(
            insert_new_certificate(&mut store, &der).unwrap(),
            TrustInsert::AlreadyPresent
        ));
        assert_eq!(store.certs().count(), 1);
    }
}
