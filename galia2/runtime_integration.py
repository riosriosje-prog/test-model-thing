"""GALIA 2.0 P10 non-invasive Legacy runtime integration shim.

This layer binds GALIA 2.0 to the *observed* Runtime.call contract of the
current TMT/GALIA Legacy ``main.py`` without importing MLX, patching Legacy,
or mutating repository files.  It provides:

* an AST-based compatibility gate for the Legacy Runtime surface;
* a one-call shadow bridge that delegates exactly once to ``runtime.call``;
* deterministic byte serialization of Legacy invocation/result observations;
* P4 LegacyAdapter capture, preserving the original Legacy return object.

P10 is deliberately not a promotion, persistence, or authority component.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import json
from typing import Any, Optional, Protocol, Tuple, runtime_checkable

from .core import Case, Receipt
from .legacy_adapter import LegacyAdapter, LegacyShadowCapture


EXPECTED_RUNTIME_METHODS: dict[str, Tuple[str, ...]] = {
    "__init__": ("self", "path", "threshold", "kwargs"),
    "save": ("self",),
    "call": ("self", "c", "n", "end", "save", "frozen"),
    "write": ("self", "b"),
    "chat": ("self", "save", "frozen"),
    "train": ("self", "save", "frozen", "dataset"),
    "now": ("self",),
    "__call__": ("self", "mode", "dataset", "save", "frozen"),
}


@runtime_checkable
class LegacyRuntimeProtocol(Protocol):
    def call(self, c: int, n: int | None, end: bool, save: bool, frozen: bool) -> Any: ...


@dataclass(frozen=True, slots=True)
class RuntimeCompatibilityReport:
    source_blob_sha: str
    compatible: bool
    runtime_class_present: bool
    missing_methods: Tuple[str, ...]
    signature_mismatches: Tuple[str, ...]
    main_guard_present: bool
    call_delegates_to_model: bool
    save_gate_present: bool
    call_returns_outputs: bool


@dataclass(frozen=True, slots=True)
class RuntimeCallObservation:
    case_id: str
    input_payload: bytes
    output_payload: bytes
    legacy_result: Any
    capture: LegacyShadowCapture
    capture_receipt: Receipt


def inspect_legacy_source(source: str, *, source_blob_sha: str) -> RuntimeCompatibilityReport:
    """Validate the Legacy ``Runtime`` surface without importing Legacy/MLX."""
    if not source_blob_sha.strip():
        raise ValueError("source_blob_sha must be non-empty")
    tree = ast.parse(source)
    runtime = next(
        (node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Runtime"),
        None,
    )
    methods: dict[str, ast.FunctionDef] = {}
    if runtime is not None:
        methods = {
            node.name: node
            for node in runtime.body
            if isinstance(node, ast.FunctionDef)
        }

    missing = tuple(sorted(name for name in EXPECTED_RUNTIME_METHODS if name not in methods))
    mismatches: list[str] = []
    for name, expected in EXPECTED_RUNTIME_METHODS.items():
        method = methods.get(name)
        if method is None:
            continue
        actual = tuple(arg.arg for arg in method.args.args)
        if method.args.kwarg is not None:
            actual = actual + (method.args.kwarg.arg,)
        if actual != expected:
            mismatches.append(name)

    call = methods.get("call")
    delegates = False
    save_gate = False
    returns_outputs = False
    if call is not None:
        for node in ast.walk(call):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "self" and node.func.attr == "model":
                    arg_names = tuple(a.id for a in node.args if isinstance(a, ast.Name))
                    if arg_names == ("c", "n", "end", "frozen"):
                        delegates = True
            if isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == "save":
                if any(
                    isinstance(x, ast.Call)
                    and isinstance(x.func, ast.Attribute)
                    and isinstance(x.func.value, ast.Name)
                    and x.func.value.id == "self"
                    and x.func.attr == "save"
                    for x in ast.walk(node)
                ):
                    save_gate = True
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Name) and node.value.id == "outputs":
                returns_outputs = True

    main_guard = False
    for node in tree.body:
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "__name__"
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == "__main__"
        ):
            main_guard = True
            break

    compatible = bool(
        runtime is not None
        and not missing
        and not mismatches
        and main_guard
        and delegates
        and save_gate
        and returns_outputs
    )
    return RuntimeCompatibilityReport(
        source_blob_sha=source_blob_sha,
        compatible=compatible,
        runtime_class_present=runtime is not None,
        missing_methods=missing,
        signature_mismatches=tuple(sorted(mismatches)),
        main_guard_present=main_guard,
        call_delegates_to_model=delegates,
        save_gate_present=save_gate,
        call_returns_outputs=returns_outputs,
    )


def _validate_byte(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
        raise ValueError(f"{name} must be an integer byte in [0, 255]")
    return value


def _invocation_payload(*, c: int, n: Optional[int], end: bool, save: bool, frozen: bool) -> bytes:
    _validate_byte("c", c)
    if n is not None:
        _validate_byte("n", n)
    if type(end) is not bool or type(save) is not bool or type(frozen) is not bool:
        raise ValueError("end/save/frozen must be bool")
    payload = {"c": c, "end": end, "frozen": frozen, "n": n, "save": save}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _result_payload(result: Any) -> bytes:
    if not isinstance(result, tuple) or len(result) != 2:
        raise TypeError("Legacy Runtime.call result must be a 2-tuple (byte, stop)")
    b, stop = result
    _validate_byte("output byte", b)
    if isinstance(stop, bool) or not isinstance(stop, (int, float)):
        raise TypeError("Legacy Runtime.call stop value must be numeric")
    payload = {"byte": b, "stop": float(stop)}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class RuntimeShadowBridge:
    """Delegate one Legacy Runtime.call and shadow-capture its exact observation.

    The bridge does not patch the runtime, invoke ``save`` independently, write
    files, alter HEAD, or make authority decisions.  Any Legacy side effect is
    solely whatever the caller explicitly requested through Legacy's own
    ``runtime.call(..., save=...)`` contract.
    """

    def __init__(self, *, adapter: LegacyAdapter, legacy_blob_sha: str) -> None:
        if not legacy_blob_sha.strip():
            raise ValueError("legacy_blob_sha must be non-empty")
        self.adapter = adapter
        self.legacy_blob_sha = legacy_blob_sha

    def invoke(
        self,
        *,
        case: Case,
        runtime: LegacyRuntimeProtocol,
        c: int,
        n: int | None,
        end: bool,
        save: bool,
        frozen: bool,
    ) -> RuntimeCallObservation:
        if not isinstance(runtime, LegacyRuntimeProtocol):
            raise TypeError("runtime must expose callable Runtime.call")
        input_payload = _invocation_payload(c=c, n=n, end=end, save=save, frozen=frozen)

        # Exactly one Legacy call.  No patching, pre-call save, post-call save,
        # or duplicated execution is permitted by this bridge.
        result = runtime.call(c, n, end, save, frozen)
        output_payload = _result_payload(result)

        op = self.adapter.capture(
            case=case,
            input_payload=input_payload,
            output_payload=output_payload,
            input_ref=f"legacy-runtime:{self.legacy_blob_sha}:call-input",
            output_ref=f"legacy-runtime:{self.legacy_blob_sha}:call-output",
        )
        return RuntimeCallObservation(
            case_id=case.case_id,
            input_payload=input_payload,
            output_payload=output_payload,
            legacy_result=result,
            capture=op.value,
            capture_receipt=op.receipt,
        )
