#!/usr/bin/env python3
"""dump_python_signatures.py — Block E parity harness, Signal 1
Python-source dumper.

Walks the openfhe Python module (openfhe-python pinned to v1.5.1.0)
via inspect.getdoc + a pybind11 docstring overload-line regex and
emits one method record per overload. The output JSON matches the
schema documented in `notes/blocks/E-bindings-rewrite/harness.md`
§2.1, so the surface-parity test in
`inst/tinytest/test_surface_parity.R` can three-way diff this against
the C++ header dump (`dump_header_signatures.R`) and the R formals
dump (`dump_r_signatures.R`).

Why this script is in Python: it has to `import openfhe` and call
`inspect.getdoc()` on pybind11-bound classes, and that only works
inside the reference venv where openfhe-python is installed. The
sibling header dumper used to live alongside this code (in a
combined `dump_signatures.py`) but was migrated to R at 9100.0
because the regex parser walks plain text and doesn't need a
Python environment. Splitting the two leaves only the genuinely
Python-only logic in this file.

inspect.signature() raises TypeError on every pybind11 method
because pybind11 emits C-level callables that Python's signature
introspection cannot read. The fallback is to parse the docstring,
which pybind11 always emits in a stable line format:

    1. MethodName(self: openfhe.CryptoContext, arg: type = default) -> openfhe.RetType

USAGE:

    /Users/naras/research/fhe/temp/openfhe-python-venv/bin/python \\
      R_dev/openfhe/inst/scripts/dump_python_signatures.py \\
      --output=/Users/naras/research/fhe/temp/scratch/signatures-python.json

The script must be run with the reference venv's Python interpreter
(it imports `openfhe` from the venv's site-packages). The venv
build steps and gotchas live in
`temp/openfhe-python-venv/README.md`.
"""

from __future__ import annotations

import argparse
import datetime
import inspect
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "1"

DEFAULT_OUTPUT = Path(
    "/Users/naras/research/fhe/temp/scratch/signatures-python.json"
)

# ---------------------------------------------------------------------------
# Type-class projection
# ---------------------------------------------------------------------------

# Bare openfhe class names that we project as their own type_class.
S7_CLASS_NAMES = {
    "CryptoContext",
    "BFVParams",
    "BGVParams",
    "CKKSParams",
    "CCParamsBFVRNS",
    "CCParamsBGVRNS",
    "CCParamsCKKSRNS",
    "PublicKey",
    "PrivateKey",
    "KeyPair",
    "Plaintext",
    "Ciphertext",
    "FastRotationPrecomputation",
    "EvalKey",
    "EvalKeyMap",
    "LWECiphertext",
    "LWEPrivateKey",
    "BinFHEContext",
    "CryptoParameters",
    "EncodingParams",
    "ElementParams",
}

ENUM_NAMES = {
    "PKESchemeFeature",
    "ScalingTechnique",
    "CKKSDataType",
    "SecurityLevel",
    "ScalingModSize",
    "ProxyReEncryptionMode",
    "DecryptionNoiseMode",
    "EncryptionTechnique",
    "SCHEME",
    "BINFHE_PARAMSET",
    "BINGATE",
    "BINFHE_METHOD",
    "BINFHE_OUTPUT",
    "MultipartyMode",
    "ExecutionMode",
    "COMPRESSION_LEVEL",
    "CompressionLevel",
    "KeySwitchTechnique",
    "MultiplicationTechnique",
    "PlaintextEncodings",
}

# Top-level classes whose methods we walk for the python dump.
PYTHON_CLASS_TARGETS = [
    "CryptoContext",
    "BinFHEContext",
    "CCParamsBFVRNS",
    "CCParamsBGVRNS",
    "CCParamsCKKSRNS",
    "KeyPair",
    "PublicKey",
    "PrivateKey",
    "Plaintext",
    "Ciphertext",
    "EvalKey",
    "EvalKeyMap",
    "LWECiphertext",
    "LWEPrivateKey",
]


def _py_type_class(annotation: str) -> str:
    """Map a Python annotation string (from a docstring or
    inspect.signature) to the harness type_class symbol."""
    a = annotation.strip()
    if not a or a == "None":
        return "void"
    # Strip openfhe. prefix
    if a.startswith("openfhe."):
        bare = a.split(".", 1)[1]
        if bare in S7_CLASS_NAMES:
            return bare
        if bare in ENUM_NAMES:
            return f"enum:{bare}"
        if bare == "ParmType":
            return "optional:CryptoParameters"
        return bare  # unknown openfhe class — emit bare name
    low = a.lower()
    # Sequence / list wrappers must be checked BEFORE the scalar
    # short-circuits below, because pybind11 emits annotations like
    # `collections.abc.Sequence[typing.SupportsInt | typing.SupportsIndex]`
    # which would otherwise match the int_scalar rule on the inner
    # SupportsInt token.
    is_seq = (
        low.startswith("list[")
        or low.startswith("collections.abc.sequence[")
        or low.startswith("sequence[")
        or low.startswith("typing.list[")
        or low.startswith("typing.sequence[")
    )
    if is_seq:
        inner = a[a.find("[") + 1:a.rfind("]")].strip().lower()
        if "complex" in inner:
            return "complex_vector"
        if "float" in inner or "double" in inner:
            return "double_vector"
        if "int" in inner or "index" in inner:
            return "int_vector"
        return "vector"
    # Plain int/float/bool/str scalars.
    if low == "int" or "supportsint" in low or ("supportsindex" in low and "supportsfloat" not in low and "supportscomplex" not in low):
        return "int_scalar"
    if low == "float" or ("supportsfloat" in low and "supportscomplex" not in low):
        return "double_scalar"
    if low == "bool":
        return "bool_scalar"
    if low == "str":
        return "string"
    if "supportscomplex" in low:
        return "complex_scalar"
    return a  # unknown — pass through


_PY_DEFAULT_INT_RE = re.compile(r"^-?\d+$")
_PY_DEFAULT_FLOAT_RE = re.compile(r"^-?\d+\.\d*([eE][+-]?\d+)?$")


def _py_default_class(default_str: Optional[str]) -> tuple[str, Any]:
    """Map a Python default literal to (default_class, default_value)."""
    if default_str is None:
        return ("none", None)
    s = default_str.strip()
    if s == "":
        return ("none", None)
    if s in ("None",):
        return ("null", None)
    if s == "True":
        return ("bool_literal", True)
    if s == "False":
        return ("bool_literal", False)
    if _PY_DEFAULT_INT_RE.match(s):
        return ("int_literal", int(s))
    if _PY_DEFAULT_FLOAT_RE.match(s):
        return ("double_literal", float(s))
    if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
        return ("string_literal", s[1:-1])
    if s in ("[]", "()"):
        return ("empty_vector", [])
    return ("non_constant", s)


# Parse a single pybind11 docstring overload signature line of the form:
#   1. MethodName(self: openfhe.CryptoContext, arg1: type1, arg2: type2 = default) -> openfhe.RetType
_OVERLOAD_LINE_RE = re.compile(
    r"^\s*(?:\d+\.\s+)?([A-Za-z_]\w*)\s*\((?P<args>.*)\)\s*->\s*(?P<ret>.+?)\s*$"
)


def _split_args_top_level(arg_str: str) -> list[str]:
    """Split a comma-separated argument list, respecting [ ], ( ), < >, |."""
    parts: list[str] = []
    depth = 0
    current = ""
    for ch in arg_str:
        if ch in "[(<":
            depth += 1
            current += ch
        elif ch in "])>":
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())
    return parts


def _parse_one_arg(piece: str) -> Optional[dict]:
    """Parse one argument piece like 'name: type = default' into the
    schema dict, or return None for a 'self' argument."""
    p = piece.strip()
    if not p:
        return None
    # Split off default at top-level '='
    default_str = None
    eq_idx = -1
    depth = 0
    for i, ch in enumerate(p):
        if ch in "[(<":
            depth += 1
        elif ch in "])>":
            depth -= 1
        elif ch == "=" and depth == 0:
            eq_idx = i
            break
    if eq_idx >= 0:
        default_str = p[eq_idx + 1:].strip()
        p = p[:eq_idx].strip()
    # Now p is "name: type" or just "name"
    if ":" in p:
        name, type_str = p.split(":", 1)
        name = name.strip()
        type_str = type_str.strip()
    else:
        name = p
        type_str = ""
    if name == "self":
        return None
    type_class = _py_type_class(type_str) if type_str else "any"
    dclass, dvalue = _py_default_class(default_str)
    out = {"name": name, "type_class": type_class, "default_class": dclass}
    if dclass != "none":
        out["default_value"] = dvalue
    return out


def _parse_overload_doc(doc: str) -> list[dict]:
    """Parse a pybind11 docstring into a list of overload records.

    Each record has keys: name, args, return_type."""
    if not doc:
        return []
    # Walk lines and find ones matching the overload-line regex.
    overloads: list[dict] = []
    for line in doc.splitlines():
        m = _OVERLOAD_LINE_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        arg_str = m.group("args")
        ret = m.group("ret").strip()
        arg_pieces = _split_args_top_level(arg_str)
        args = []
        for piece in arg_pieces:
            parsed = _parse_one_arg(piece)
            if parsed is not None:
                args.append(parsed)
        overloads.append({
            "name": name,
            "return_type": _py_type_class(ret),
            "args": args,
        })
    return overloads


def _python_dump_method(class_name: str, method_name: str, method_obj: Any) -> list[dict]:
    """Return a list of method records for one (class, method) pair.

    pybind11 overloaded methods produce N records; non-overloaded
    methods produce 1; uninspectable methods produce a single
    'uninspectable' record."""
    doc = inspect.getdoc(method_obj) or ""
    overloads = _parse_overload_doc(doc)
    if overloads:
        out = []
        for ov in overloads:
            out.append({
                "class": class_name,
                "name": method_name,
                "kind": "method",
                "return_type": ov["return_type"],
                "args": ov["args"],
            })
        return out
    # Fall back to inspect.signature() for pure-Python wrappers.
    try:
        sig = inspect.signature(method_obj)
        args = []
        for pname, p in sig.parameters.items():
            if pname == "self":
                continue
            type_str = (
                str(p.annotation)
                if p.annotation is not inspect.Parameter.empty
                else ""
            )
            type_class = _py_type_class(type_str) if type_str else "any"
            if p.default is inspect.Parameter.empty:
                dclass, dvalue = "none", None
            else:
                dclass, dvalue = _py_default_class(repr(p.default))
            entry = {"name": pname, "type_class": type_class, "default_class": dclass}
            if dclass != "none":
                entry["default_value"] = dvalue
            args.append(entry)
        return [{
            "class": class_name,
            "name": method_name,
            "kind": "method",
            "return_type": "any",
            "args": args,
        }]
    except (TypeError, ValueError):
        pass
    return [{
        "class": class_name,
        "name": method_name,
        "kind": "uninspectable",
        "doc": doc[:500],
    }]


def dump_python(output: Path) -> None:
    import openfhe  # noqa: F401  -- imported for side-effects / class lookup

    methods: list[dict] = []
    for class_name in PYTHON_CLASS_TARGETS:
        cls = getattr(openfhe, class_name, None)
        if cls is None:
            continue
        for member_name in sorted(dir(cls)):
            if member_name.startswith("_"):
                continue
            try:
                member = getattr(cls, member_name)
            except Exception:
                continue
            if not callable(member):
                continue
            records = _python_dump_method(class_name, member_name, member)
            methods.extend(records)

    # Free functions of interest at the openfhe top level.
    free_function_targets = [
        "GenCryptoContext",
        "ReleaseAllContexts",
        "ClearEvalMultKeys",
        "ClearEvalAutomorphismKeys",
        "ClearEvalSumKeys",
        "EvalChebyshevCoefficients",
    ]
    for fname in free_function_targets:
        f = getattr(openfhe, fname, None)
        if f is None:
            continue
        records = _python_dump_method("<module>", fname, f)
        methods.extend(records)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "source": "python",
        "package_version": getattr(openfhe, "__version__", "unknown"),
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exported_count": len(methods),
        "methods": methods,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w") as fh:
        json.dump(payload, fh, indent=2, default=str)
    print(f"[dump_python_signatures] wrote {len(methods)} methods to {output}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Block E parity harness Python-source signature dumper")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="output JSON path",
    )
    args = parser.parse_args(argv)
    dump_python(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
