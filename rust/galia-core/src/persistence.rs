//! GALIA P7 byte-exact, READ-ONLY persistence/replay verifier.
//! The objects represent supplied bytes, not a trusted disk or authoritative store.
//! No file I/O, HEAD CAS, receipt issuance, authorization verification or promotion.
use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn hex_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn required(s: &str) -> bool { !s.trim().is_empty() }
fn segment_safe(s: &str) -> bool {
    required(s) && s != "." && s != ".." && !s.chars().any(|c| matches!(c, '/' | '\\' | ':' | '\0'))
}
fn path_safe(s: &str) -> bool {
    if !required(s) || s.starts_with('/') || s.starts_with("payload/") || s.contains('\\') || s.contains(':') || s.contains('\0') {
        return false;
    }
    let parts: Vec<&str> = s.split('/').collect();
    !parts.iter().any(|p| p.is_empty() || *p == "." || *p == "..")
        && !matches!(s, "HEAD" | "manifest.json" | "promotion.json")
}
fn timestamp_safe(s: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(s).is_ok()
}
fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let ordered = serde_json::to_value(value).map_err(|e| e.to_string())?;
    serde_json::to_vec(&ordered).map_err(|e| e.to_string())
}
fn decode(data: &str, title: &str) -> Result<Vec<u8>, String> {
    hex::decode(data).map_err(|_| format!("{title}: invalid hex"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadEntry {
    pub path: String,
    pub sha256: String,
    pub byte_size: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationManifest {
    pub commit_id: String,
    pub seq: u64,
    pub parent_commit: String,
    pub case_id: String,
    pub schema_version: String,
    pub created_at: String,
    pub payloads: Vec<PayloadEntry>,
    pub authority_decision_id: String,
    pub persistence_policy_version: String,
}
impl GenerationManifest {
    fn validate(&self) -> Result<(), String> {
        if !segment_safe(&self.commit_id) || !segment_safe(&self.parent_commit)
            || !required(&self.case_id) || !required(&self.schema_version)
            || !required(&self.authority_decision_id)
            || !required(&self.persistence_policy_version)
            || self.seq == 0 || self.commit_id == self.parent_commit
            || !timestamp_safe(&self.created_at) {
            return Err("invalid generation manifest identity/timestamp/sequence".into());
        }
        if self.payloads.is_empty() {
            return Err("manifest requires at least one payload".into());
        }
        let mut paths = BTreeSet::new();
        for p in &self.payloads {
            if !path_safe(&p.path) || !hex_sha(&p.sha256) || !paths.insert(p.path.clone()) {
                return Err("invalid/duplicate payload path or SHA-256".into());
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionEnvelope {
    pub commit_id: String,
    pub case_id: String,
    pub manifest_hash: String,
    pub authority_decision_id: String,
    pub authorization_id: String,
    pub authorization_policy_version: String,
    pub preflight_receipt_id: String,
    pub persistence_policy_version: String,
    pub published_at: String,
}
impl PromotionEnvelope {
    fn validate(&self) -> Result<(), String> {
        if !segment_safe(&self.commit_id) || !required(&self.case_id)
            || !hex_sha(&self.manifest_hash) || !required(&self.authority_decision_id)
            || !required(&self.authorization_id)
            || !required(&self.authorization_policy_version)
            || !required(&self.preflight_receipt_id)
            || !required(&self.persistence_policy_version)
            || !timestamp_safe(&self.published_at) {
            return Err("invalid promotion envelope structure".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadPointer {
    pub commit_id: String,
    pub seq: u64,
    pub manifest_hash: String,
    pub promotion_hash: String,
}
impl HeadPointer {
    fn validate(&self) -> Result<(), String> {
        if !segment_safe(&self.commit_id) || self.seq == 0
            || !hex_sha(&self.manifest_hash) || !hex_sha(&self.promotion_hash) {
            return Err("invalid HEAD pointer".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBytes {
    /// Canonical, exact bytes of Python P7 GenerationManifest.to_bytes() hex-encoded.
    pub manifest_hex: String,
    /// Canonical, exact bytes of Python P7 PromotionEnvelope.to_bytes() hex-encoded.
    pub promotion_hex: String,
    /// Exact bytes of Python P7 HeadPointer.to_bytes() hex-encoded.
    pub head_hex: String,
    /// Exact content bytes for all declared payloads; no undeclared extras.
    pub payloads_hex: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRequest {
    pub generation: GenerationBytes,
    #[serde(default)]
    pub parent: Option<GenerationBytes>,
}
#[derive(Clone, Debug, Serialize)]
pub struct VerificationReport {
    pub status: &'static str,
    pub evidence_kind: &'static str,
    pub integrity_consistent: bool,
    pub parent_chain_checked: bool,
    pub commit_id: String,
    pub seq: u64,
    pub manifest_hash: String,
    pub promotion_hash: String,
    pub canonical_writeback: bool,
    pub authority_transfer: bool,
    pub output_commit: Option<String>,
}

struct VerifiedGeneration {
    manifest: GenerationManifest,
    head: HeadPointer,
    manifest_hash: String,
    promotion_hash: String,
}

/// Byte-level verification of a SUPPLIED immutable generation snapshot. No writes.
fn verify_one(bundle: &GenerationBytes) -> Result<VerifiedGeneration, String> {
    let manifest_raw = decode(&bundle.manifest_hex, "manifest")?;
    let promotion_raw = decode(&bundle.promotion_hex, "promotion")?;
    let head_raw = decode(&bundle.head_hex, "HEAD")?;
    let manifest: GenerationManifest = serde_json::from_slice(&manifest_raw)
        .map_err(|e| format!("invalid manifest JSON: {e}"))?;
    let promotion: PromotionEnvelope = serde_json::from_slice(&promotion_raw)
        .map_err(|e| format!("invalid promotion JSON: {e}"))?;
    let head: HeadPointer = serde_json::from_slice(&head_raw)
        .map_err(|e| format!("invalid HEAD JSON: {e}"))?;
    manifest.validate()?;
    promotion.validate()?;
    head.validate()?;
    // Stronger than legacy: reject noncanonical JSON / duplicate keys / whitespace / malleation.
    if canonical_bytes(&manifest)? != manifest_raw {
        return Err("manifest bytes are not canonical".into());
    }
    if canonical_bytes(&promotion)? != promotion_raw {
        return Err("promotion bytes are not canonical".into());
    }
    let mut expected_head_bytes = canonical_bytes(&head)?;
    expected_head_bytes.push(b'\n');
    if expected_head_bytes != head_raw {
        return Err("HEAD bytes are not canonical".into());
    }
    let mh = digest(&manifest_raw);
    let ph = digest(&promotion_raw);
    if mh != head.manifest_hash || ph != head.promotion_hash
        || mh != promotion.manifest_hash {
        return Err("HEAD/promotion/manifest SHA-256 mismatch".into());
    }
    if manifest.commit_id != head.commit_id || manifest.commit_id != promotion.commit_id
        || manifest.seq != head.seq {
        return Err("HEAD/manifest/promotion commit or sequence mismatch".into());
    }
    if promotion.case_id != manifest.case_id
        || promotion.authority_decision_id != manifest.authority_decision_id
        || promotion.persistence_policy_version != manifest.persistence_policy_version {
        return Err("promotion envelope identity/policy binding mismatch".into());
    }
    let declared: BTreeSet<&str> = manifest.payloads.iter().map(|e| e.path.as_str()).collect();
    let actual: BTreeSet<&str> = bundle.payloads_hex.keys().map(String::as_str).collect();
    if declared != actual {
        return Err("missing/undeclared payloads".into());
    }
    for entry in &manifest.payloads {
        let raw = decode(&bundle.payloads_hex[&entry.path], "payload")?;
        if raw.len() as u64 != entry.byte_size || digest(&raw) != entry.sha256 {
            return Err(format!("payload size/SHA-256 mismatch: {}", entry.path));
        }
    }
    Ok(VerifiedGeneration {manifest, head, manifest_hash:mh, promotion_hash:ph})
}

/// Pure verification of candidate plus optional parent. This is NOT an authorization
/// or a claim that inputs were independently collected from the actual canonical store.
pub fn verify_request(req: &VerificationRequest) -> Result<VerificationReport, String> {
    let child = verify_one(&req.generation)?;
    if let Some(parent_bytes) = &req.parent {
        let parent = verify_one(parent_bytes)?;
        if child.manifest.parent_commit != parent.head.commit_id
            || child.manifest.seq != parent.head.seq.checked_add(1).ok_or("sequence overflow")?
            || child.manifest.case_id != parent.manifest.case_id {
            return Err("candidate parent/sequence/case chain mismatch".into());
        }
    }
    Ok(VerificationReport {
        status: "ADVISORY_ONLY",
        evidence_kind: "SUPPLIED_BYTES_INTEGRITY_ONLY",
        integrity_consistent: true,
        parent_chain_checked: req.parent.is_some(),
        commit_id: child.manifest.commit_id,
        seq: child.manifest.seq,
        manifest_hash: child.manifest_hash,
        promotion_hash: child.promotion_hash,
        canonical_writeback: false,
        authority_transfer: false,
        output_commit: None,
    })
}
