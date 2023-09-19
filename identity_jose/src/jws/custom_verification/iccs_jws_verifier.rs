use super::*;
use crate::jwk::{BlsCurve, Jwk, JwkParamsOkp, JwkType};
use crate::jws::{
  Decoder, JwsAlgorithm, JwsHeader, JwsVerifier, SignatureVerificationError, SignatureVerificationErrorKind,
};
use crate::jwu::{decode_b64, encode_b64};
use candid::Principal;
use ic_certification::{Certificate, Delegation, HashTree, LookupResult};
use ic_certified_map::Hash;
use ic_verify_bls_signature::verify_bls_signature;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::ops::Deref;
use std::sync::RwLock;

const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";
const IC_ROOT_KEY_DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
const IC_ROOT_KEY_DER: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";
const IC_ROOT_KEY_LENGTH: usize = 96;

const CANISTER_KEY_DER_PREFIX_LENGTH: usize = 19;
// Canister signatures' public key OID is 1.3.6.1.4.1.56387.1.2,
// cf. https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures
const CANISTER_KEY_DER_OID: &[u8; 14] = b"\x30\x0C\x06\x0A\x2B\x06\x01\x04\x01\x83\xB8\x43\x01\x02";

/// An implementor of [`JwsVerifier`] that can handle the
/// [`JwsAlgorithm::IcCs`](crate::jws::JwsAlgorithm::IcCs) algorithm.
///
/// See [`Self::verify`](IcCsJwsVerifier::verify).
///
/// NOTE: This type can only be constructed when the `iccs` feature is enabled.
#[derive(Debug)]
#[non_exhaustive]
pub struct IcCsJwsVerifier;

#[derive(Serialize, Deserialize)]
struct IcCsSig {
  certificate: ByteBuf,
  tree: HashTree,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct IcCsPublicKey {
  signing_canister_id: Principal,
  #[serde(with = "serde_bytes")]
  seed: Vec<u8>,
}

impl TryFrom<&[u8]> for IcCsPublicKey {
  type Error = SignatureVerificationError;

  fn try_from(der_pubkey_bytes: &[u8]) -> Result<Self, Self::Error> {
    // TODO: check the entire DER-structure.
    let oid_part = &der_pubkey_bytes[2..(CANISTER_KEY_DER_OID.len() + 2)];
    if oid_part[..] != CANISTER_KEY_DER_OID[..] {
      return Err(key_decoding_err("invalid OID of canister key"));
    }
    let bitstring_offset: usize = CANISTER_KEY_DER_PREFIX_LENGTH;
    let canister_id_len: usize = if der_pubkey_bytes.len() > bitstring_offset {
      usize::from(der_pubkey_bytes[bitstring_offset])
    } else {
      return Err(key_decoding_err("canister key shorter than DER prefix"));
    };
    if der_pubkey_bytes.len() < (bitstring_offset + 1 + canister_id_len) {
      return Err(key_decoding_err("canister key too short"));
    }
    let canister_id_raw = &der_pubkey_bytes[(bitstring_offset + 1)..(bitstring_offset + 1 + canister_id_len)];
    let seed = &der_pubkey_bytes[bitstring_offset + canister_id_len + 1..];

    let canister_id = Principal::try_from_slice(canister_id_raw)
      .map_err(|e| key_decoding_err(&format!("invalid canister id in canister pk: {}", e)))?;
    Ok(IcCsPublicKey {
      signing_canister_id: canister_id,
      seed: seed.to_vec(),
    })
  }
}

impl IcCsJwsVerifier {
  pub fn verify_iccs(input: VerificationInput, _bls_pk_jwk: &Jwk) -> Result<(), SignatureVerificationError> {
    let iccs_sig: IcCsSig = serde_cbor::from_slice(&input.decoded_signature)
      .map_err(|e| invalid_signature_err(&format!("signature parsing error: {}", e)))?;
    let ic_certificate: Certificate = serde_cbor::from_slice(iccs_sig.certificate.as_ref())
      .map_err(|e| key_decoding_err(&format!("certificate parsing error: {}", e)))?;

    let jws_header = input
      .protected_header
      .ok_or(invalid_signature_err("missing protected header in verification input"))?;
    let iccs_pk = get_canister_signing_pk(&jws_header)?;

    ///// Check if root hash of the signatures hash tree matches the certified data in the certificate
    let certified_data_path = [b"canister", iccs_pk.signing_canister_id.as_slice(), b"certified_data"];
    // Get value of the certified data in the certificate
    let witness = match ic_certificate.tree.lookup_path(&certified_data_path) {
      LookupResult::Found(witness) => witness,
      _ => {
        return Err(invalid_signature_err(&format!(
          "certificate tree has no certified data witness for canister {} (0x{})",
          iccs_pk.signing_canister_id.to_text(),
          hex::encode(iccs_pk.signing_canister_id.as_slice())
        )))
      }
    };
    // Recompute the root hash of the signatures hash tree
    let digest = iccs_sig.tree.digest();

    if witness != digest {
      return Err(invalid_signature_err(
        "certificate tree witness doesn't match signature tree digest",
      ));
    }

    ///// Check canister-specific certification path.
    let seed_hash = hash_bytes_sha256(&iccs_pk.seed);
    let signing_input_hash = verifiable_credential_signing_input_hash(&input.signing_input);
    let cert_sig_path = [b"sig", &seed_hash[..], &signing_input_hash[..]];
    match iccs_sig.tree.lookup_path(&cert_sig_path) {
      LookupResult::Found(_) => {}
      _ => {
        return Err(invalid_signature_err(
          "missing signature path in canister's certified data",
        ))
      }
    }

    /////  Verify BLS signature on the root hash.
    verify_root_signature(&ic_certificate, iccs_pk.signing_canister_id)
  }
}

impl JwsVerifier for IcCsJwsVerifier {
  fn verify(&self, input: VerificationInput, public_key: &Jwk) -> Result<(), SignatureVerificationError> {
    IcCsJwsVerifier::verify_iccs(input, public_key)
  }
}

fn unsupported_alg_err(custom_message: &str) -> SignatureVerificationError {
  let err: SignatureVerificationError = SignatureVerificationErrorKind::UnsupportedAlg.into();
  err.with_custom_message(custom_message.to_string())
}

fn key_decoding_err(custom_message: &str) -> SignatureVerificationError {
  let err: SignatureVerificationError = SignatureVerificationErrorKind::KeyDecodingFailure.into();
  err.with_custom_message(custom_message.to_string())
}

fn invalid_signature_err(custom_message: &str) -> SignatureVerificationError {
  let err: SignatureVerificationError = SignatureVerificationErrorKind::InvalidSignature.into();
  err.with_custom_message(custom_message.to_string())
}

fn unspecified_err(custom_message: &str) -> SignatureVerificationError {
  let err: SignatureVerificationError = SignatureVerificationErrorKind::Unspecified.into();
  err.with_custom_message(custom_message.to_string())
}

fn extract_ic_root_key_from_der(buf: &[u8]) -> Result<Vec<u8>, SignatureVerificationError> {
  let expected_length = IC_ROOT_KEY_DER_PREFIX.len() + IC_ROOT_KEY_LENGTH;
  if buf.len() != expected_length {
    return Err(key_decoding_err("invalid root key length"));
  }

  let prefix = &buf[0..IC_ROOT_KEY_DER_PREFIX.len()];
  if prefix[..] != IC_ROOT_KEY_DER_PREFIX[..] {
    return Err(key_decoding_err("invalid root key prefix"));
  }

  let key = &buf[IC_ROOT_KEY_DER_PREFIX.len()..];
  Ok(key.to_vec())
}

fn hash_bytes_sha256(bytes: &[u8]) -> Hash {
  let mut hasher = Sha256::new();
  hasher.update(bytes);
  hasher.finalize().into()
}

fn verifiable_credential_signing_input_hash(signing_input: &[u8]) -> Hash {
  let sep = b"iccs_verifiable_credential";
  let mut hasher = Sha256::new();
  let buf = [sep.len() as u8];
  hasher.update(buf);
  hasher.update(sep);
  hasher.update(signing_input);
  hasher.finalize().into()
}

fn get_canister_signing_pk(jws_header: &JwsHeader) -> Result<IcCsPublicKey, SignatureVerificationError> {
  let jwk = jws_header
    .deref()
    .jwk()
    .ok_or(key_decoding_err("missing JWK in JWS header"))?;
  if jwk.alg() != Some("IcCs") {
    return Err(unsupported_alg_err("expected IcCs"));
  }
  // Per https://datatracker.ietf.org/doc/html/rfc7518#section-6.4,
  // JwkParamsOct are for symmetric keys or another key whose value is a single octet sequence.
  if jwk.kty() != JwkType::Oct {
    return Err(unsupported_alg_err("expected JWK of type oct"));
  }
  let jwk_params = jwk
    .try_oct_params()
    .map_err(|_| key_decoding_err("missing JWK oct params"))?;
  let pk_der = decode_b64(jwk_params.k.as_bytes()).map_err(|_| key_decoding_err("invalid base64url encoding"))?;
  IcCsPublicKey::try_from(pk_der.as_slice())
}

#[allow(dead_code)]
fn get_root_pk(bls_pk_jwk: &Jwk) -> Result<Vec<u8>, SignatureVerificationError> {
  if bls_pk_jwk.alg() != Some("Bls12381") {
    return Err(unsupported_alg_err("expected Bls12381"));
  }
  if bls_pk_jwk.kty() != JwkType::Okp {
    return Err(unsupported_alg_err("expected JWK of type okp"));
  }
  let jwk_params = bls_pk_jwk
    .try_okp_params()
    .map_err(|_| key_decoding_err("missing JWK okp params"))?;
  if jwk_params.crv != "Bls12381G1" {
    return Err(key_decoding_err(&format!("unsupported curve {}", jwk_params.crv)));
  }
  let pk_der = decode_b64(jwk_params.x.as_bytes()).map_err(|_| key_decoding_err("invalid base64url encoding"))?;
  if pk_der.len() != IC_ROOT_KEY_LENGTH {
    return Err(key_decoding_err(&format!(
      "expected {} bytes for BLS public key",
      IC_ROOT_KEY_LENGTH
    )));
  }
  Ok(pk_der)
}

// cf. https://datatracker.ietf.org/doc/draft-ietf-cose-bls-key-representations/
// currently JwkParamsOkp does not have y-field, so putting the entire public key into x,
// according to the serialization of ic_verify_bls_signature::PublicKey.
pub fn bls_pk_jwk(ic_root_pk_der: &[u8], kid: &str) -> Result<Jwk, SignatureVerificationError> {
  let mut public_key_jwk = Jwk::new(JwkType::Okp);
  public_key_jwk.set_kid(kid);
  public_key_jwk.set_alg("Bls12381");
  let pk_bytes = extract_ic_root_key_from_der(ic_root_pk_der)?;
  public_key_jwk
    .set_params(JwkParamsOkp {
      crv: BlsCurve::Bls12381G1.name().to_owned(),
      x: encode_b64(pk_bytes),
      d: None,
    })
    .unwrap();
  public_key_jwk.set_alg(JwsAlgorithm::Bls12381.to_string());
  Ok(public_key_jwk)
}

lazy_static! {
  static ref IC_ROOT_PUBLIC_KEY: RwLock<Vec<u8>> =
    RwLock::new(extract_ic_root_key_from_der(IC_ROOT_KEY_DER).expect("Failed decoding IC root key."));
}

pub fn set_ic_root_public_key_for_testing(pk_der: Vec<u8>) {
  let mut root_pk = IC_ROOT_PUBLIC_KEY.write().unwrap();
  *root_pk = extract_ic_root_key_from_der(&pk_der).expect("Failed decoding IC root key.");
}

// Checks if a principal is contained within a list of principal ranges
// A range is a tuple: (low: Principal, high: Principal), as described here: https://docs.dfinity.systems/spec/public/#state-tree-subnet
// Taken from https://github.com/dfinity/agent-rs/blob/60f7a0db21688ca423dee0bb150e142a03e925c6/ic-agent/src/agent/mod.rs#L784
fn principal_is_within_ranges(principal: &Principal, ranges: &[(Principal, Principal)]) -> bool {
  ranges.iter().any(|r| principal >= &r.0 && principal <= &r.1)
}

/// Verifies the specified JWS credential against the given root public key.
#[allow(dead_code)]
pub fn verify_credential_jws(
  credential_jws: &str,
  signing_canister_id: Principal,
) -> Result<(), SignatureVerificationError> {
  ///// Decode JWS.
  let decoder: Decoder = Decoder::new();
  let jws = decoder
    .decode_compact_serialization(credential_jws.as_ref(), None)
    .map_err(|e| key_decoding_err(&format!("credential JWS parsing error: {}", e)))?;
  let iccs_sig: IcCsSig = serde_cbor::from_slice(&jws.decoded_signature())
    .map_err(|e| invalid_signature_err(&format!("signature parsing error: {}", e)))?;
  let ic_certificate: Certificate = serde_cbor::from_slice(iccs_sig.certificate.as_ref())
    .map_err(|e| key_decoding_err(&format!("certificate parsing error: {}", e)))?;
  let jws_header = jws.protected_header().ok_or(key_decoding_err("missing JWS header"))?;
  let iccs_pk = get_canister_signing_pk(&jws_header)?;

  ///// Check if root hash of the signatures hash tree matches the certified data in the certificate
  let certified_data_path = [b"canister", iccs_pk.signing_canister_id.as_slice(), b"certified_data"];
  // Get value of the certified data in the certificate
  let witness = match ic_certificate.tree.lookup_path(&certified_data_path) {
    LookupResult::Found(witness) => witness,
    _ => {
      return Err(invalid_signature_err(&format!(
        "certificate tree has no certified data witness for canister {} (0x{})",
        iccs_pk.signing_canister_id.to_text(),
        hex::encode(iccs_pk.signing_canister_id.as_slice())
      )))
    }
  };
  // Recompute the root hash of the signatures hash tree
  let digest = iccs_sig.tree.digest();

  if witness != digest {
    return Err(invalid_signature_err(
      "certificate tree witness doesn't match signature tree digest",
    ));
  }

  ///// Check the certification path.
  let seed_hash = hash_bytes_sha256(&iccs_pk.seed);
  let signing_input_hash = verifiable_credential_signing_input_hash(jws.signing_input());
  let cert_sig_path = [b"sig", &seed_hash[..], &signing_input_hash[..]];
  match iccs_sig.tree.lookup_path(&cert_sig_path) {
    LookupResult::Found(_) => {}
    _ => {
      return Err(invalid_signature_err(
        "missing signature path in canister's certified data",
      ))
    }
  }

  ///// Verify BLS signature on the root hash.
  verify_root_signature(&ic_certificate, signing_canister_id)
}

fn verify_root_signature(
  ic_certificate: &Certificate,
  signing_canister_id: Principal,
) -> Result<(), SignatureVerificationError> {
  let signing_pk = validate_delegation(&ic_certificate.delegation, signing_canister_id)?;
  let root_hash = ic_certificate.tree.digest();
  let mut msg = vec![];
  msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
  msg.extend_from_slice(&root_hash);

  if verify_bls_signature(&ic_certificate.signature, &msg, &signing_pk).is_err() {
    return Err(invalid_signature_err("invalid BLS signature"));
  }
  Ok(())
}

fn validate_delegation(
  delegation: &Option<Delegation>,
  signing_canister_id: Principal,
) -> Result<Vec<u8>, SignatureVerificationError> {
  match delegation {
    None => {
      let root_pk = IC_ROOT_PUBLIC_KEY
        .read()
        .map_err(|_| unspecified_err("Internal error accessing IC root public key"))?;
      Ok(root_pk.to_owned())
    }
    Some(delegation) => {
      let cert: Certificate = serde_cbor::from_slice(&delegation.certificate)
        .map_err(|_| invalid_signature_err("Failed parsing CBOR delegation certificate"))?;
      let _ = verify_root_signature(&cert, signing_canister_id)?;
      let canister_range_path = [b"subnet", delegation.subnet_id.as_slice(), b"canister_ranges"];
      let LookupResult::Found(canister_range) = cert.tree.lookup_path(&canister_range_path) else {
        return Err(invalid_signature_err("Delegation invalid"));
      };
      let ranges: Vec<(Principal, Principal)> = serde_cbor::from_slice(canister_range)
        .map_err(|_| invalid_signature_err("Failed parsing CBOR delegation canister range"))?;
      if !principal_is_within_ranges(&signing_canister_id, &ranges[..]) {
        return Err(invalid_signature_err(
          "The certificate is not authorized to answer calls for this canister",
        ));
      }

      let public_key_path = [b"subnet", delegation.subnet_id.as_slice(), b"public_key"];
      let LookupResult::Found(pk) = cert.tree.lookup_path(&public_key_path) else {
        return Err(invalid_signature_err("Invalid delegation"));
      };
      let raw_pk = extract_ic_root_key_from_der(pk)?;
      Ok(raw_pk)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::jws::JwsAlgorithm;
  use assert_matches::assert_matches;
  use candid::Principal;
  use ic_cbor::CertificateToCbor;
  use ic_certification_testing::CertificateBuilder;
  use ic_response_verification_test_utils::AssetTree;
  use serial_test::serial;

  fn principal_from_u64(i: u64) -> Principal {
    let mut bytes: Vec<u8> = i.to_be_bytes().to_vec();
    // Append 0x01 twice, to be compatible with CanisterId::from_u64() used by response_verification
    bytes.push(0x01);
    bytes.push(0x01);
    Principal::from_slice(&bytes)
  }

  const TEST_SIGNING_CANISTER_ID: &str = "rwlgt-iiaaa-aaaaa-aaaaa-cai";
  const TEST_IC_ROOT_PK_B64URL: &str = "MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAK32VjilMFayIiyRuyRXsCdLypUZilrL2t_n_XIXjwab3qjZnpR52Ah6Job8gb88SxH-J1Vw1IHxaY951Giv4OV6zB4pj4tpeY2nqJG77Blwk-xfR1kJkj1Iv-1oQ9vtHw";
  const ID_ALIAS_CREDENTIAL_JWS: &str = "eyJqd2siOnsia3R5Ijoib2N0IiwiYWxnIjoiSWNDcyIsImsiOiJNRHd3REFZS0t3WUJCQUdEdUVNQkFnTXNBQW9BQUFBQUFBQUFBQUVCamxUYzNvSzVRVU9SbUt0T3YyVXBhMnhlQW5vNEJ4RlFFYmY1VWRUSTZlYyJ9LCJraWQiOiJkaWQ6aWM6aWktY2FuaXN0ZXIiLCJhbGciOiJJY0NzIn0.eyJpc3MiOiJodHRwczovL2ludGVybmV0Y29tcHV0ZXIub3JnL2lzc3VlcnMvaW50ZXJuZXQtaWRlbml0eSIsIm5iZiI6MTYyMDMyODYzMCwianRpIjoiaHR0cHM6Ly9pbnRlcm5ldGNvbXB1dGVyLm9yZy9jcmVkZW50aWFsL2ludGVybmV0LWlkZW5pdHkiLCJzdWIiOiJkaWQ6d2ViOmNwZWhxLTU0aGVmLW9kamp0LWJvY2tsLTNsZHRnLWpxbGU0LXlzaTVyLTZiZmFoLXY2bHNhLXhwcmR2LXBxZSIsInZjIjp7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSW50ZXJuZXRJZGVudGl0eUlkQWxpYXMiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaGFzX2lkX2FsaWFzIjoiZGlkOndlYjpzMzNxYy1jdG5wNS11Ynl6NC1rdWJxby1wMnRlbS1oZTRscy02ajIzai1od3diYS0zN3pibC10Mmx2My1wYWUifX19.2dn3omtjZXJ0aWZpY2F0ZVkBi9nZ96JkdHJlZYMBgwGDAYMCSGNhbmlzdGVygwJKAAAAAAAAAAABAYMBgwGDAYMCTmNlcnRpZmllZF9kYXRhggNYIODv9b076dlspbUFOyPWJHgYNK9z1_e5ch1_xbztAGgGggRYINLM_z_MXakw3sDoSiVB5lhRa0uxUB5w6LQQ5phqBX1gggRYIBfmGXVF1WCWPapsKI5MoFLJ55x11hQqSb_sRnrp5hFVggRYIMJ9utEUSVVFIqnKBAQ0yrssMWD36ZH2cUb60yoTOzKAggRYIAL_4M5TY9ONUOV0m4NnJ0sP4qs6Dbmt_TfyJW2VcHCtggRYILRWoDKnWsPosTjq1xLq2WPAg0ONkxqUY8Gr7IJiDAYdgwGCBFggNVP2WB1Ts90nZG9hyLDaCww4gbhXxtw8R-poiMET62uDAkR0aW1lggNJgLiu1N2JpL4WaXNpZ25hdHVyZVgwheosd0fsVnQbYtorM71pkwAG4ENhEI84F_xk7uwBeY_4DlNnMdTHFYpLErOXbuS3ZHRyZWWDAYIEWCDvRfWrF74pofmWJkBxcTtb2rClPh4tQ3qWj25MVh-S64MCQ3NpZ4MCWCA6UuW6rWVPRqQn_k-pP9kMNe6RKs1gj7QVCsaG4Bx2OYMBgwJYIDAugH-BjrALnLxVtfR0ayNY5_9_Vc9oVt-H5hpWFVWXggNAggRYIC0ZLl16DWYaDIXJg88YBHdXKqdVgPyXZaZtE6_LgyZR";
  const ID_ALIAS_CREDENTIAL_JWS_NO_JWK: &str = "eyJraWQiOiJkaWQ6aWM6aWktY2FuaXN0ZXIiLCJhbGciOiJJY0NzIn0.eyJpc3MiOiJodHRwczovL2ludGVybmV0Y29tcHV0ZXIub3JnL2lzc3VlcnMvaW50ZXJuZXQtaWRlbml0eSIsIm5iZiI6MTYyMDMyODYzMCwianRpIjoiaHR0cHM6Ly9pbnRlcm5ldGNvbXB1dGVyLm9yZy9jcmVkZW50aWFsL2ludGVybmV0LWlkZW5pdHkiLCJzdWIiOiJkaWQ6d2ViOmNwZWhxLTU0aGVmLW9kamp0LWJvY2tsLTNsZHRnLWpxbGU0LXlzaTVyLTZiZmFoLXY2bHNhLXhwcmR2LXBxZSIsInZjIjp7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSW50ZXJuZXRJZGVudGl0eUlkQWxpYXMiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaGFzX2lkX2FsaWFzIjoiZGlkOndlYjpzMzNxYy1jdG5wNS11Ynl6NC1rdWJxby1wMnRlbS1oZTRscy02ajIzai1od3diYS0zN3pibC10Mmx2My1wYWUifX19.2dn3omtjZXJ0aWZpY2F0ZVkBi9nZ96JkdHJlZYMBgwGDAYMCSGNhbmlzdGVygwJKAAAAAAAAAAABAYMBgwGDAYMCTmNlcnRpZmllZF9kYXRhggNYIG3uU_jutBtXB-of0uEA3RkCrcunK6D8QFPtX-gDSwDeggRYINLM_z_MXakw3sDoSiVB5lhRa0uxUB5w6LQQ5phqBX1gggRYIMULjwe1N6XomH10SEyc2r_uc7mGf1aSadeDaid9cUrkggRYIDw__VW2PgWMFp6mK-GmPG-7Fc90q58oK_wjcJ3IrkToggRYIAQTcQAtnxsa93zbfZEZV0f28OhiXL5Wp1OAyDHNI_x4ggRYINkQ8P9zGUvsVi3XbQ2bs6V_3kAiN8UNM6yPgeXfmArEgwGCBFggNVP2WB1Ts90nZG9hyLDaCww4gbhXxtw8R-poiMET62uDAkR0aW1lggNJgLiu1N2JpL4WaXNpZ25hdHVyZVgwqHrYoUsNvSEaSShbW8barx0_ODXD5ZBEl9nKOdkNy_fBmGErE_C7ILbC91_fyZ7CZHRyZWWDAYIEWCB223o-sI97tc3LwJL3LRxQ4If6v_IvfC1fwIGYYQ9vroMCQ3NpZ4MCWCA6UuW6rWVPRqQn_k-pP9kMNe6RKs1gj7QVCsaG4Bx2OYMBgwJYIHszMLDS2VadioIaHajRY5iJzroqMs63lVrs_Uj42j0sggNAggRYICm0w_XxGEw4fDPoYcojCILEi0qdH4-4Zw7klzdaPNOC";

  fn test_ic_root_pk_der() -> Vec<u8> {
    decode_b64(TEST_IC_ROOT_PK_B64URL).expect("failure decoding canister pk")
  }

  #[test]
  #[serial]
  fn should_verify_id_alias_vc_jws() {
    set_ic_root_public_key_for_testing(test_ic_root_pk_der());
    let signing_canister_id = Principal::from_text(TEST_SIGNING_CANISTER_ID).expect("failed parsing canister id");
    verify_credential_jws(ID_ALIAS_CREDENTIAL_JWS, signing_canister_id).expect("JWS verification failed");
  }

  #[test]
  fn should_not_verify_id_alias_vc_jws_without_canister_pk() {
    let signing_canister_id = Principal::from_text(TEST_SIGNING_CANISTER_ID).expect("failed parsing canister id");
    let result = verify_credential_jws(ID_ALIAS_CREDENTIAL_JWS_NO_JWK, signing_canister_id);
    assert_matches!(result, Err(e) if e.to_string().contains("missing JWK in JWS header"));
  }

  #[test]
  #[serial]
  fn should_not_verify_id_alias_vc_jws_with_wrong_root_pk() {
    let signing_canister_id = Principal::from_text(TEST_SIGNING_CANISTER_ID).expect("failed parsing canister id");
    let mut ic_root_pk_der = test_ic_root_pk_der();
    ic_root_pk_der[IC_ROOT_KEY_DER_PREFIX.len()] = ic_root_pk_der[IC_ROOT_KEY_DER_PREFIX.len()] + 1; // change the root pk value
    set_ic_root_public_key_for_testing(ic_root_pk_der);
    let result = verify_credential_jws(ID_ALIAS_CREDENTIAL_JWS, signing_canister_id);
    assert_matches!(result, Err(e) if e.to_string().contains("invalid BLS signature"));
  }

  #[test]
  #[serial]
  fn should_verify_id_alias_via_jws_verifier() {
    set_ic_root_public_key_for_testing(test_ic_root_pk_der());
    let decoder: Decoder = Decoder::new();
    let jws = decoder
      .decode_compact_serialization(ID_ALIAS_CREDENTIAL_JWS.as_ref(), None)
      .expect("failed parsing JWS");
    let verification_input = VerificationInput {
      alg: JwsAlgorithm::IcCs,
      signing_input: Box::from(jws.signing_input()),
      decoded_signature: Box::from(jws.decoded_signature()),
      protected_header: Some(jws.protected_header().expect("missing protected header").clone()),
    };
    let bls_pk_jwk = bls_pk_jwk(&test_ic_root_pk_der(), "did:ic:0x123#ic-root-public-key").expect("invalid root pk");
    IcCsJwsVerifier::verify_iccs(verification_input, &bls_pk_jwk).expect("JWS verification failed");
  }

  #[test]
  #[serial]
  fn should_verify_root_signature_without_delegation() {
    let signing_canister_id = Principal::from_text(TEST_SIGNING_CANISTER_ID).expect("failed parsing canister id");

    let ic_cert_data =
      CertificateBuilder::new(&signing_canister_id.to_string(), &AssetTree::new().get_certified_data())
        .expect("CertificateBuilder creation failed")
        .build()
        .expect("Certificate creation failed");
    set_ic_root_public_key_for_testing(ic_cert_data.root_key);
    let ic_certificate =
      Certificate::from_cbor(&ic_cert_data.cbor_encoded_certificate).expect("CBOR cert parsing failed");

    verify_root_signature(&ic_certificate, signing_canister_id).expect("Verification without delegation failed");
  }

  #[test]
  #[serial]
  fn should_verify_root_signature_with_delegation() {
    let signing_canister_id = principal_from_u64(5);
    let subnet_id = 123u64;
    let ic_cert_data =
      CertificateBuilder::new(&signing_canister_id.to_string(), &AssetTree::new().get_certified_data())
        .expect("CertificateBuilder creation failed")
        .with_delegation(subnet_id, vec![(0, 10)])
        .build()
        .expect("Certificate creation failed");
    set_ic_root_public_key_for_testing(ic_cert_data.root_key);
    let ic_certificate =
      Certificate::from_cbor(&ic_cert_data.cbor_encoded_certificate).expect("CBOR cert parsing failed");

    verify_root_signature(&ic_certificate, signing_canister_id).expect("Verification with delegation failed");
  }

  #[test]
  #[serial]
  fn should_fail_verify_root_signature_with_delegation_if_canister_not_in_range() {
    let signing_canister_id = principal_from_u64(42);
    let subnet_id = 123u64;
    let ic_cert_data =
      CertificateBuilder::new(&signing_canister_id.to_string(), &AssetTree::new().get_certified_data())
        .expect("CertificateBuilder creation failed")
        .with_delegation(subnet_id, vec![(0, 10)])
        .build()
        .expect("Certificate creation failed");
    set_ic_root_public_key_for_testing(ic_cert_data.root_key);
    let ic_certificate =
      Certificate::from_cbor(&ic_cert_data.cbor_encoded_certificate).expect("CBOR cert parsing failed");

    let result = verify_root_signature(&ic_certificate, signing_canister_id);
    assert_matches!(result, Err(e) if e.to_string().contains("not authorized to answer calls for this canister"));
  }

  #[test]
  #[serial]
  fn should_fail_verify_root_signature_with_delegation_if_invalid_signature() {
    let signing_canister_id = principal_from_u64(5);
    let subnet_id = 123u64;
    let ic_cert_data =
      CertificateBuilder::new(&signing_canister_id.to_string(), &AssetTree::new().get_certified_data())
        .expect("CertificateBuilder creation failed")
        .with_delegation(subnet_id, vec![(0, 10)])
        .with_invalid_signature()
        .build()
        .expect("Certificate creation failed");
    set_ic_root_public_key_for_testing(ic_cert_data.root_key);
    let ic_certificate =
      Certificate::from_cbor(&ic_cert_data.cbor_encoded_certificate).expect("CBOR cert parsing failed");

    let result = verify_root_signature(&ic_certificate, signing_canister_id);
    assert_matches!(result, Err(e) if e.to_string().contains("invalid BLS signature"));
  }
}
