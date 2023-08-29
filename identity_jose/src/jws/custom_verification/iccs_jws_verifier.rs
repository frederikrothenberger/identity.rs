use super::*;
use crate::jwk::Jwk;
use crate::jws::{Decoder, JwsVerifier, SignatureVerificationError, SignatureVerificationErrorKind};
use crate::jwu::decode_b64;
use candid::Principal;
use ic_certification::{Certificate, HashTree, LookupResult};
use ic_certified_map::Hash;
use ic_verify_bls_signature::verify_bls_signature;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";
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
  pub fn verify_iccs(input: VerificationInput, public_key: &Jwk) -> Result<(), SignatureVerificationError> {
    let iccs_sig: IcCsSig = serde_cbor::from_slice(&input.decoded_signature)
      .map_err(|e| invalid_signature_err(&format!("signature parsing error: {}", e)))?;
    let certificate: Certificate = serde_cbor::from_slice(iccs_sig.certificate.as_ref())
      .map_err(|e| key_decoding_err(&format!("certificate parsing error: {}", e)))?;

    public_key
      .check_alg("IcCs")
      .map_err(|e| unsupported_alg_err(&format!("iccs not supported: {}", e)))?;
    // Per https://datatracker.ietf.org/doc/html/rfc7518#section-6.4,
    // JwkParamsOct are for symmetric keys or another key whose value is a single octet sequence.
    let key_params = public_key
      .try_oct_params()
      .map_err(|e| key_decoding_err(&format!("oct-params not found : {}", e)))?;
    let pubkey_bytes =
      decode_b64(key_params.k.as_bytes()).map_err(|e| key_decoding_err(&format!("oct-params parsing error: {}", e)))?;
    let iccs_pk = IcCsPublicKey::try_from(pubkey_bytes.as_slice())?;

    ///// Check if root hash of the signatures hash tree matches the certified data in the certificate
    let certified_data_path = [b"canister", iccs_pk.signing_canister_id.as_slice(), b"certified_data"];
    // Get value of the certified data in the certificate
    let witness = match certificate.tree.lookup_path(&certified_data_path) {
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
    let signing_input_hash = id_alias_signing_input_hash(&input.signing_input);
    let cert_sig_path = [b"sig", &seed_hash[..], &signing_input_hash[..]];
    match iccs_sig.tree.lookup_path(&cert_sig_path) {
      LookupResult::Found(_) => {}
      _ => {
        return Err(invalid_signature_err(
          "missing signature path in canister's certified data",
        ))
      }
    }

    /////  TODO: Verify BLS signature on the root hash.

    Ok(())
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

fn id_alias_signing_input_hash(signing_input: &[u8]) -> Hash {
  let sep = b"iccs_verifiable_credential";
  let mut hasher = Sha256::new();
  let buf = [sep.len() as u8];
  hasher.update(buf);
  hasher.update(sep);
  hasher.update(signing_input);
  hasher.finalize().into()
}

/// Verifies the specified JWS credential against the given canister signatures' public key
/// and the root public key.
// TODO: enable customized path checking via a function-parameter
// TODO: enable validation of claims
#[allow(dead_code)]
pub fn verify_id_alias_jws(
  credential_jws: &str,
  iccs_pk_der: &[u8],
  ic_root_pk_der: &[u8],
) -> Result<(), SignatureVerificationError> {
  ///// Decode JWS.
  let decoder: Decoder = Decoder::new();
  let jws = decoder
    .decode_compact_serialization(credential_jws.as_ref(), None)
    .map_err(|e| key_decoding_err(&format!("credential JWS parsing error: {}", e)))?;
  let iccs_sig: IcCsSig = serde_cbor::from_slice(&jws.decoded_signature())
    .map_err(|e| invalid_signature_err(&format!("signature parsing error: {}", e)))?;
  let certificate: Certificate = serde_cbor::from_slice(iccs_sig.certificate.as_ref())
    .map_err(|e| key_decoding_err(&format!("certificate parsing error: {}", e)))?;
  let iccs_pk = IcCsPublicKey::try_from(iccs_pk_der)?;

  ///// Check if root hash of the signatures hash tree matches the certified data in the certificate
  let certified_data_path = [b"canister", iccs_pk.signing_canister_id.as_slice(), b"certified_data"];
  // Get value of the certified data in the certificate
  let witness = match certificate.tree.lookup_path(&certified_data_path) {
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
  let signing_input_hash = id_alias_signing_input_hash(jws.signing_input());
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
  let root_key = extract_ic_root_key_from_der(ic_root_pk_der)?;
  let root_hash = certificate.tree.digest();
  let mut msg = vec![];
  msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
  msg.extend_from_slice(&root_hash);
  if verify_bls_signature(&certificate.signature, &msg, &root_key).is_err() {
    return Err(invalid_signature_err("invalid BLS signature"));
  }

  Ok(())
}
#[cfg(test)]
mod tests {
  use super::*;
  use crate::jwk::{JwkParams, JwkParamsOct, JwkType};
  use crate::jws::JwsAlgorithm;
  use crate::jwu::encode_b64;
  use assert_matches::assert_matches;

  const ROOT_PK_B64URL: &str = "MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAK32VjilMFayIiyRuyRXsCdLypUZilrL2t_n_XIXjwab3qjZnpR52Ah6Job8gb88SxH-J1Vw1IHxaY951Giv4OV6zB4pj4tpeY2nqJG77Blwk-xfR1kJkj1Iv-1oQ9vtHw";
  const CANISTER_SIG_PK_B64URL: &str =
    "MDwwDAYKKwYBBAGDuEMBAgMsAAoAAAAAAAAAAAEBjlTc3oK5QUORmKtOv2Upa2xeAno4BxFQEbf5UdTI6ec";
  const ID_ALIAS_CREDENTIAL_JWS: &str = "eyJraWQiOiJkaWQ6aWM6aWktY2FuaXN0ZXIiLCJhbGciOiJJY0NzIn0.eyJpc3MiOiJodHRwczovL2ludGVybmV0Y29tcHV0ZXIub3JnL2lzc3VlcnMvaW50ZXJuZXQtaWRlbml0eSIsIm5iZiI6MTYyMDMyODYzMCwianRpIjoiaHR0cHM6Ly9pbnRlcm5ldGNvbXB1dGVyLm9yZy9jcmVkZW50aWFsL2ludGVybmV0LWlkZW5pdHkiLCJzdWIiOiJkaWQ6d2ViOmNwZWhxLTU0aGVmLW9kamp0LWJvY2tsLTNsZHRnLWpxbGU0LXlzaTVyLTZiZmFoLXY2bHNhLXhwcmR2LXBxZSIsInZjIjp7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSW50ZXJuZXRJZGVudGl0eUlkQWxpYXMiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaGFzX2lkX2FsaWFzIjoiZGlkOndlYjpzMzNxYy1jdG5wNS11Ynl6NC1rdWJxby1wMnRlbS1oZTRscy02ajIzai1od3diYS0zN3pibC10Mmx2My1wYWUifX19.2dn3omtjZXJ0aWZpY2F0ZVkBi9nZ96JkdHJlZYMBgwGDAYMCSGNhbmlzdGVygwJKAAAAAAAAAAABAYMBgwGDAYMCTmNlcnRpZmllZF9kYXRhggNYIG3uU_jutBtXB-of0uEA3RkCrcunK6D8QFPtX-gDSwDeggRYINLM_z_MXakw3sDoSiVB5lhRa0uxUB5w6LQQ5phqBX1gggRYIMULjwe1N6XomH10SEyc2r_uc7mGf1aSadeDaid9cUrkggRYIDw__VW2PgWMFp6mK-GmPG-7Fc90q58oK_wjcJ3IrkToggRYIAQTcQAtnxsa93zbfZEZV0f28OhiXL5Wp1OAyDHNI_x4ggRYINkQ8P9zGUvsVi3XbQ2bs6V_3kAiN8UNM6yPgeXfmArEgwGCBFggNVP2WB1Ts90nZG9hyLDaCww4gbhXxtw8R-poiMET62uDAkR0aW1lggNJgLiu1N2JpL4WaXNpZ25hdHVyZVgwqHrYoUsNvSEaSShbW8barx0_ODXD5ZBEl9nKOdkNy_fBmGErE_C7ILbC91_fyZ7CZHRyZWWDAYIEWCB223o-sI97tc3LwJL3LRxQ4If6v_IvfC1fwIGYYQ9vroMCQ3NpZ4MCWCA6UuW6rWVPRqQn_k-pP9kMNe6RKs1gj7QVCsaG4Bx2OYMBgwJYIHszMLDS2VadioIaHajRY5iJzroqMs63lVrs_Uj42j0sggNAggRYICm0w_XxGEw4fDPoYcojCILEi0qdH4-4Zw7klzdaPNOC";

  fn root_and_canister_public_keys_der() -> (Vec<u8>, Vec<u8>) {
    (
      decode_b64(ROOT_PK_B64URL).expect("failure decoding canister pk"),
      decode_b64(CANISTER_SIG_PK_B64URL).expect("failure decoding canister pk"),
    )
  }

  #[test]
  fn should_verify_id_alias_vc_jws() {
    let (ic_root_pk_der, iccs_pk_der) = root_and_canister_public_keys_der();
    verify_id_alias_jws(ID_ALIAS_CREDENTIAL_JWS, &iccs_pk_der, &ic_root_pk_der).expect("JWS verification failed");
  }

  #[test]
  fn should_not_verify_id_alias_vc_jws_with_wrong_canister_pk() {
    let (ic_root_pk_der, mut iccs_pk_der) = root_and_canister_public_keys_der();
    iccs_pk_der[25] = iccs_pk_der[25] + 1; // change the canister id
    let result = verify_id_alias_jws(ID_ALIAS_CREDENTIAL_JWS, &iccs_pk_der, &ic_root_pk_der);
    assert_matches!(result, Err(e) if e.to_string().contains("no certified data witness for canister"))
  }

  #[test]
  fn should_not_verify_id_alias_vc_jws_with_wrong_root_pk() {
    let (mut ic_root_pk_der, iccs_pk_der) = root_and_canister_public_keys_der();
    ic_root_pk_der[IC_ROOT_KEY_DER_PREFIX.len()] = ic_root_pk_der[IC_ROOT_KEY_DER_PREFIX.len()] + 1; // change the root pk value
    let result = verify_id_alias_jws(ID_ALIAS_CREDENTIAL_JWS, &iccs_pk_der, &ic_root_pk_der);
    assert_matches!(result, Err(e) if e.to_string().contains("invalid BLS signature"))
  }

  #[test]
  fn should_verify_id_alias_via_jws_verifier() {
    let (_ic_root_pk_der, iccs_pk_der) = root_and_canister_public_keys_der();
    let decoder: Decoder = Decoder::new();
    let jws = decoder
      .decode_compact_serialization(ID_ALIAS_CREDENTIAL_JWS.as_ref(), None)
      .expect("failed parsing JWS");
    let verification_input = VerificationInput {
      alg: JwsAlgorithm::IcCs,
      signing_input: Box::from(jws.signing_input()),
      decoded_signature: Box::from(jws.decoded_signature()),
    };
    let mut iccs_pk_jwk = Jwk::new(JwkType::Oct);
    iccs_pk_jwk
      .set_params(JwkParams::Oct(JwkParamsOct {
        k: encode_b64(iccs_pk_der),
      }))
      .expect("failed setting JWK params");
    IcCsJwsVerifier::verify_iccs(verification_input, &iccs_pk_jwk).expect("JWS verification failed");
  }
}
