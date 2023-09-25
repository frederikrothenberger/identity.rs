use super::*;
use crate::jwk::{BlsCurve, Jwk, JwkParamsOkp, JwkType};
use crate::jws::{JwsAlgorithm, JwsHeader, JwsVerifier, SignatureVerificationError, SignatureVerificationErrorKind};
use crate::jwu::{decode_b64, encode_b64};
use candid::Principal;
use canister_sig_util::verify_root_signature;
use ic_certification::{Certificate, HashTree, LookupResult};
use ic_certified_map::Hash;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::ops::Deref;

const IC_ROOT_KEY_DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
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
      .map_err(|e| invalid_signature_err(&format!("{:?}", e)))
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::jws::{Decoder, JwsAlgorithm};
  use canister_sig_util::set_ic_root_public_key_for_testing;
  use serial_test::serial;

  const TEST_IC_ROOT_PK_B64URL: &str = "MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAK32VjilMFayIiyRuyRXsCdLypUZilrL2t_n_XIXjwab3qjZnpR52Ah6Job8gb88SxH-J1Vw1IHxaY951Giv4OV6zB4pj4tpeY2nqJG77Blwk-xfR1kJkj1Iv-1oQ9vtHw";
  const ID_ALIAS_CREDENTIAL_JWS: &str = "eyJqd2siOnsia3R5Ijoib2N0IiwiYWxnIjoiSWNDcyIsImsiOiJNRHd3REFZS0t3WUJCQUdEdUVNQkFnTXNBQW9BQUFBQUFBQUFBQUVCamxUYzNvSzVRVU9SbUt0T3YyVXBhMnhlQW5vNEJ4RlFFYmY1VWRUSTZlYyJ9LCJraWQiOiJkaWQ6aWM6aWktY2FuaXN0ZXIiLCJhbGciOiJJY0NzIn0.eyJpc3MiOiJodHRwczovL2ludGVybmV0Y29tcHV0ZXIub3JnL2lzc3VlcnMvaW50ZXJuZXQtaWRlbml0eSIsIm5iZiI6MTYyMDMyODYzMCwianRpIjoiaHR0cHM6Ly9pbnRlcm5ldGNvbXB1dGVyLm9yZy9jcmVkZW50aWFsL2ludGVybmV0LWlkZW5pdHkiLCJzdWIiOiJkaWQ6d2ViOmNwZWhxLTU0aGVmLW9kamp0LWJvY2tsLTNsZHRnLWpxbGU0LXlzaTVyLTZiZmFoLXY2bHNhLXhwcmR2LXBxZSIsInZjIjp7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSW50ZXJuZXRJZGVudGl0eUlkQWxpYXMiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaGFzX2lkX2FsaWFzIjoiZGlkOndlYjpzMzNxYy1jdG5wNS11Ynl6NC1rdWJxby1wMnRlbS1oZTRscy02ajIzai1od3diYS0zN3pibC10Mmx2My1wYWUifX19.2dn3omtjZXJ0aWZpY2F0ZVkBi9nZ96JkdHJlZYMBgwGDAYMCSGNhbmlzdGVygwJKAAAAAAAAAAABAYMBgwGDAYMCTmNlcnRpZmllZF9kYXRhggNYIODv9b076dlspbUFOyPWJHgYNK9z1_e5ch1_xbztAGgGggRYINLM_z_MXakw3sDoSiVB5lhRa0uxUB5w6LQQ5phqBX1gggRYIBfmGXVF1WCWPapsKI5MoFLJ55x11hQqSb_sRnrp5hFVggRYIMJ9utEUSVVFIqnKBAQ0yrssMWD36ZH2cUb60yoTOzKAggRYIAL_4M5TY9ONUOV0m4NnJ0sP4qs6Dbmt_TfyJW2VcHCtggRYILRWoDKnWsPosTjq1xLq2WPAg0ONkxqUY8Gr7IJiDAYdgwGCBFggNVP2WB1Ts90nZG9hyLDaCww4gbhXxtw8R-poiMET62uDAkR0aW1lggNJgLiu1N2JpL4WaXNpZ25hdHVyZVgwheosd0fsVnQbYtorM71pkwAG4ENhEI84F_xk7uwBeY_4DlNnMdTHFYpLErOXbuS3ZHRyZWWDAYIEWCDvRfWrF74pofmWJkBxcTtb2rClPh4tQ3qWj25MVh-S64MCQ3NpZ4MCWCA6UuW6rWVPRqQn_k-pP9kMNe6RKs1gj7QVCsaG4Bx2OYMBgwJYIDAugH-BjrALnLxVtfR0ayNY5_9_Vc9oVt-H5hpWFVWXggNAggRYIC0ZLl16DWYaDIXJg88YBHdXKqdVgPyXZaZtE6_LgyZR";

  fn test_ic_root_pk_der() -> Vec<u8> {
    decode_b64(TEST_IC_ROOT_PK_B64URL).expect("failure decoding canister pk")
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
}
