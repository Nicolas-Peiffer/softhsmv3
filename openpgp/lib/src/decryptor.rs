use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
use sequoia_openpgp::types::SymmetricAlgorithm;

use crate::Op11KeyPair;

impl sequoia_openpgp::crypto::Decryptor for Op11KeyPair {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &sequoia_openpgp::crypto::mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> sequoia_openpgp::Result<SessionKey> {
        match ciphertext {
            sequoia_openpgp::crypto::mpi::Ciphertext::RSA { c: cipher } => {
                let session = self.session.lock().unwrap();
                let decrypted =
                    session.decrypt(&Mechanism::RsaPkcs, self.private, cipher.value())?;
                Ok(decrypted.as_slice().into())
            }
            sequoia_openpgp::crypto::mpi::Ciphertext::ECDH { ref e, .. } => {
                let field_sz = 256; // FIXME?

                use cryptoki::mechanism::elliptic_curve::*;

                let bytes = e.value();

                let params = Ecdh1DeriveParams {
                    kdf: EcKdfType::NULL,
                    shared_data_len: 0_usize.try_into()?,
                    shared_data: std::ptr::null(),
                    public_data_len: (*bytes).len().try_into()?,
                    public_data: bytes.as_ptr() as *const std::ffi::c_void,
                };

                let res = self.session.lock().unwrap().derive_key(
                    &Mechanism::Ecdh1Derive(params),
                    self.private,
                    &[
                        Attribute::Class(ObjectClass::SECRET_KEY),
                        Attribute::KeyType(KeyType::GENERIC_SECRET),
                        Attribute::Token(false),
                        Attribute::Sensitive(false),
                        Attribute::Extractable(true),
                        Attribute::Encrypt(true),
                        Attribute::Decrypt(true),
                        Attribute::Wrap(true),
                        Attribute::Unwrap(true),
                    ],
                );
                if let Ok(key) = res {
                    let mut value = None;
                    for attribute in self
                        .session
                        .lock()
                        .unwrap()
                        .get_attributes(key, &[AttributeType::Value])?
                    {
                        if let Attribute::Value(val) = attribute {
                            value = Some(val);
                        }
                    }

                    let value = value.unwrap();

                    let mut value = value;
                    while value.len() < (field_sz + 7) / 8 {
                        value.insert(0, 0);
                    }

                    let ret = sequoia_openpgp::crypto::ecdh::decrypt_unwrap(
                        self.public(),
                        &value.into(),
                        ciphertext,
                    );
                    if let Err(ref e) = ret {
                        println!("Err = {e:?}");
                    }
                    ret
                } else {
                    eprintln!("Err = {res:?}");
                    Err(
                        sequoia_openpgp::Error::InvalidOperation("derive_key() failed".to_string())
                            .into(),
                    )
                }
            }
            _ => Err(sequoia_openpgp::Error::InvalidOperation(
                "Unexpected Ciphertext type.".to_string(),
            )
            .into()),
        }
    }
}

impl VerificationHelper for Op11KeyPair {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
        // Return public keys for signature verification here.
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        // Implement your signature verification policy here.
        Ok(())
    }
}

impl DecryptionHelper for Op11KeyPair {
    fn decrypt<D>(
        &mut self,
        pkesks: &[sequoia_openpgp::packet::PKESK],
        _skesks: &[sequoia_openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let mut pair = Op11KeyPair {
            public: self.public.clone(),
            session: self.session.clone(),
            private: self.private,
        };

        pkesks[0]
            .decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        // XXX: In production code, return the Fingerprint of the
        // recipient's Cert here
        Ok(None)
    }
}
