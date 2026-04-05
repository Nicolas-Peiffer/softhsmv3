use crate::constants::*;
use xmss::*;

pub static mut KAT_SEED: Option<[u8; 96]> = None;

pub fn xmss_keygen(xmss_param: u32) -> Result<(Vec<u8>, Vec<u8>), ()> {
    macro_rules! dispatch {
        ($t:ty) => {{
            let mut seed = [0u8; 96];
            unsafe {
                if let Some(kat) = KAT_SEED {
                    seed.copy_from_slice(&kat);
                } else {
                    getrandom::getrandom(&mut seed).map_err(|_| ())?;
                }
            }
            let mut kp = KeyPair::<$t>::from_seed(&seed).map_err(|_| ())?;
            Ok((kp.verifying_key().as_ref().to_vec(), kp.signing_key().as_ref().to_vec()))
        }};
    }
    match xmss_param {
        CKP_XMSS_SHA2_10_256 => dispatch!(XmssSha2_10_256),
        CKP_XMSS_SHA2_16_256 => dispatch!(XmssSha2_16_256),
        CKP_XMSS_SHA2_20_256 => dispatch!(XmssSha2_20_256),
        CKP_XMSS_SHAKE_10_256 => dispatch!(XmssShake_10_256),
        CKP_XMSS_SHAKE_16_256 => dispatch!(XmssShake_16_256),
        CKP_XMSS_SHAKE_20_256 => dispatch!(XmssShake_20_256),
        _ => Err(()),
    }
}

pub fn xmss_sign(xmss_param: u32, priv_key: &[u8], msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), u32> {
    macro_rules! dispatch {
        ($t:ty) => {{
            let mut sk = SigningKey::<$t>::try_from(priv_key).map_err(|_| CKR_FUNCTION_FAILED)?;
            let sig = sk.sign_detached(msg).map_err(|_| CKR_FUNCTION_FAILED)?;
            Ok((sig.as_ref().to_vec(), sk.as_ref().to_vec()))
        }};
    }
    match xmss_param {
        CKP_XMSS_SHA2_10_256 => dispatch!(XmssSha2_10_256),
        CKP_XMSS_SHA2_16_256 => dispatch!(XmssSha2_16_256),
        CKP_XMSS_SHA2_20_256 => dispatch!(XmssSha2_20_256),
        CKP_XMSS_SHAKE_10_256 => dispatch!(XmssShake_10_256),
        CKP_XMSS_SHAKE_16_256 => dispatch!(XmssShake_16_256),
        CKP_XMSS_SHAKE_20_256 => dispatch!(XmssShake_20_256),
        _ => Err(CKR_FUNCTION_FAILED),
    }
}

pub fn xmss_verify(xmss_param: u32, pub_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    macro_rules! dispatch {
        ($t:ty) => {{
            let pk = match VerifyingKey::<$t>::try_from(pub_key) {
                Ok(k) => k,
                Err(_) => return false,
            };
            let s = match DetachedSignature::<$t>::try_from(sig) {
                Ok(s) => s,
                Err(_) => return false,
            };
            pk.verify_detached(&s, msg).is_ok()
        }};
    }
    match xmss_param {
        CKP_XMSS_SHA2_10_256 => dispatch!(XmssSha2_10_256),
        CKP_XMSS_SHA2_16_256 => dispatch!(XmssSha2_16_256),
        CKP_XMSS_SHA2_20_256 => dispatch!(XmssSha2_20_256),
        CKP_XMSS_SHAKE_10_256 => dispatch!(XmssShake_10_256),
        CKP_XMSS_SHAKE_16_256 => dispatch!(XmssShake_16_256),
        CKP_XMSS_SHAKE_20_256 => dispatch!(XmssShake_20_256),
        _ => false,
    }
}
