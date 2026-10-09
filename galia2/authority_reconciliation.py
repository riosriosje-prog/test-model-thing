"""GALIA F22 — fail-closed external authority reconciliation.

Candidate-only POC. canonical_effect=NONE; master_promotion_state=AUTHORITY_HOLD.
F22 reconciles evidence-backed F21/F20/F19 authority candidates. It cannot
promote GALIA master, close BYTE_IDENTITY/F5, or rewrite upstream history.
"""
from __future__ import annotations
import hashlib, json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List

SCHEMA="GALIA-F22-RECONCILIATION/2"
DECISION_SCHEMA="GALIA-F22-HUMAN-DECISION/1"
STATUSES={"CONFLICT_DETECTED","NON_OVERLAPPING_COMPATIBLE","SAME_KEY_CORROBORATED","AUTHORITY_UNRESOLVED","HUMAN_SELECTION_REQUIRED","RECONCILED_BY_EXPLICIT_HUMAN_DECISION"}

def _canonical_json(obj:Any)->bytes:
    return (json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def _hash(obj:Any)->str: return hashlib.sha256(_canonical_json(obj)).hexdigest()
def _is_hash(v:Any)->bool: return isinstance(v,str) and len(v)==64 and all(c in "0123456789abcdefABCDEF" for c in v)
def _dt(v:str)->datetime:
    if not isinstance(v,str) or not v.endswith("Z"): raise ValueError("UTC timestamp required")
    return datetime.fromisoformat(v[:-1]+"+00:00").astimezone(timezone.utc)

def candidate_core(c:Dict[str,Any])->Dict[str,Any]:
    req=("candidate_id","provider_id","scope","key_id","key_sha256","source_artifact_sha256","lineage_sha256","valid_from_utc","authority_assertion")
    for k in req:
        if not c.get(k): raise ValueError("candidate missing "+k)
    for k in ("key_sha256","source_artifact_sha256","lineage_sha256"):
        if not _is_hash(c[k]): raise ValueError(k+" malformed")
    if c["authority_assertion"] not in {"ACTIVE","REVOKED"}: raise ValueError("invalid authority_assertion")
    start=_dt(c["valid_from_utc"]); end=_dt(c["valid_until_utc"]) if c.get("valid_until_utc") else None
    if end and end<=start: raise ValueError("invalid authority interval")
    return {k:c.get(k) for k in sorted(set(c)|{"valid_until_utc"}) if k!="candidate_sha256"}

def seal_candidate(c:Dict[str,Any])->Dict[str,Any]:
    r=dict(c); r["candidate_sha256"]=_hash(candidate_core(r)); return r
def validate_candidate(c:Dict[str,Any])->None:
    if not _is_hash(c.get("candidate_sha256")) or c["candidate_sha256"]!=_hash(candidate_core(c)): raise ValueError("candidate hash mismatch")
def overlaps(a,b)->bool:
    if a["provider_id"]!=b["provider_id"] or a["scope"]!=b["scope"]: return False
    inf=datetime.max.replace(tzinfo=timezone.utc)
    a1=_dt(a["valid_until_utc"]) if a.get("valid_until_utc") else inf
    b1=_dt(b["valid_until_utc"]) if b.get("valid_until_utc") else inf
    return max(_dt(a["valid_from_utc"]),_dt(b["valid_from_utc"]))<min(a1,b1)
def candidate_set_hash(cs):
    return _hash([{"candidate_id":c["candidate_id"],"candidate_sha256":c["candidate_sha256"]} for c in sorted(cs,key=lambda x:x["candidate_id"])])

def _conflict_components(conflicts):
    adjacency={}
    for a,b in conflicts:
        adjacency.setdefault(a,set()).add(b); adjacency.setdefault(b,set()).add(a)
    components=[]; seen=set()
    for root in sorted(adjacency):
        if root in seen: continue
        stack=[root]; component=set()
        while stack:
            node=stack.pop()
            if node in seen: continue
            seen.add(node); component.add(node); stack.extend(adjacency.get(node,()))
        components.append(sorted(component))
    return components

def conflict_component_hash(component,candidates):
    ids=set(component)
    return candidate_set_hash([c for c in candidates if c["candidate_id"] in ids])

def reconcile(candidates:List[Dict[str,Any]],human_decision:Dict[str,Any]|None=None)->Dict[str,Any]:
    if len(candidates)<2: raise ValueError("F22 requires >=2 candidates")
    for c in candidates: validate_candidate(c)
    ids=[c["candidate_id"] for c in candidates]
    if len(ids)!=len(set(ids)): raise ValueError("duplicate candidate_id")
    set_hash=candidate_set_hash(candidates); conflicts=[]; corroborations=[]; compatible=[]
    for i,a in enumerate(candidates):
        for b in candidates[i+1:]:
            same=a["provider_id"]==b["provider_id"] and a["scope"]==b["scope"]
            if not same or not overlaps(a,b): compatible.append([a["candidate_id"],b["candidate_id"]])
            elif a["key_id"]==b["key_id"] and a["key_sha256"]==b["key_sha256"] and a["authority_assertion"]==b["authority_assertion"]: corroborations.append([a["candidate_id"],b["candidate_id"]])
            else: conflicts.append([a["candidate_id"],b["candidate_id"]])
    conflict_state="CONFLICT_DETECTED" if conflicts else None
    authority_state="AUTHORITY_UNRESOLVED" if conflicts else ("SAME_KEY_CORROBORATED" if corroborations else "NON_OVERLAPPING_COMPATIBLE")
    action_required="HUMAN_SELECTION_REQUIRED" if conflicts else None
    components=_conflict_components(conflicts)
    component_records=[{"candidate_ids":comp,"component_sha256":conflict_component_hash(comp,candidates),"authority_state":"AUTHORITY_UNRESOLVED"} for comp in components]
    selected=None; reconciled_component_sha256=None
    if human_decision is not None:
        if not conflicts: raise ValueError("human selection only valid for unresolved conflict")
        if human_decision.get("schema_version")!=DECISION_SCHEMA: raise ValueError("decision schema mismatch")
        if human_decision.get("candidate_set_sha256")!=set_hash: raise ValueError("decision candidate set mismatch")
        selected=human_decision.get("selected_candidate_id")
        if selected not in ids: raise ValueError("selected candidate absent")
        decision_component=human_decision.get("conflict_component_sha256")
        matching=[r for r in component_records if r["component_sha256"]==decision_component]
        if len(matching)!=1: raise ValueError("decision conflict component mismatch")
        if selected not in matching[0]["candidate_ids"]: raise ValueError("selected candidate outside conflict component")
        if human_decision.get("decision")!="SELECT_AUTHORITY": raise ValueError("explicit SELECT_AUTHORITY required")
        if not _is_hash(human_decision.get("decision_sha256")): raise ValueError("decision_sha256 malformed")
        expected=_hash({k:v for k,v in human_decision.items() if k!="decision_sha256"})
        if human_decision["decision_sha256"]!=expected: raise ValueError("decision self-hash mismatch")
        matching[0]["authority_state"]="RECONCILED_BY_EXPLICIT_HUMAN_DECISION"; reconciled_component_sha256=decision_component
        unresolved=[r for r in component_records if r["authority_state"]=="AUTHORITY_UNRESOLVED"]
        if unresolved:
            authority_state="AUTHORITY_UNRESOLVED"; action_required="HUMAN_SELECTION_REQUIRED"
        else:
            authority_state="RECONCILED_BY_EXPLICIT_HUMAN_DECISION"; action_required=None
    result={"schema_version":SCHEMA,"control_id":"GALIA-F22","conflict_state":conflict_state,"authority_state":authority_state,"action_required":action_required,
      "candidate_set_sha256":set_hash,"candidate_ids":sorted(ids),"candidate_hashes":{c["candidate_id"]:c["candidate_sha256"] for c in candidates},
      "conflicts":conflicts,"conflict_components":component_records,"same_key_corroborations":corroborations,"compatible_pairs":compatible,"selected_candidate_id":selected,"reconciled_component_sha256":reconciled_component_sha256,
      "preserved_candidates":deepcopy(candidates),"canonical_effect":"NONE","master_promotion_state":"AUTHORITY_HOLD","byte_identity_effect":"NONE","f5_effect":"NONE",
      "invariants":["NO_AUTOMATIC_WINNER","RECENCY_IS_NOT_AUTHORITY","MAJORITY_IS_NOT_AUTHORITY","SIGNATURE_VALID_IS_NOT_KEY_AUTHORITY","F22_EXTERNAL_AUTHORITY_IS_NOT_GALIA_MASTER_AUTHORITY","REJECTED_CANDIDATES_REMAIN_PRESERVED","CONFLICT_HISTORY_PERSISTS_AFTER_RECONCILIATION"]}
    result["reconciliation_sha256"]=_hash(result); return result

def make_human_decision(candidates:List[Dict[str,Any]],selected_candidate_id:str,review_id:str="HR-F22",conflict_component_sha256:str|None=None)->Dict[str,Any]:
    result=reconcile(candidates)
    components=[r for r in result["conflict_components"] if selected_candidate_id in r["candidate_ids"]]
    if conflict_component_sha256 is None:
        if len(components)!=1: raise ValueError("selected candidate must identify exactly one conflict component")
        conflict_component_sha256=components[0]["component_sha256"]
    core={"schema_version":DECISION_SCHEMA,"decision":"SELECT_AUTHORITY","review_id":review_id,"candidate_set_sha256":candidate_set_hash(candidates),"conflict_component_sha256":conflict_component_sha256,"selected_candidate_id":selected_candidate_id}
    core["decision_sha256"]=_hash(core); return core
