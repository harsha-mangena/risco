from __future__ import annotations

import re
from dataclasses import dataclass, field

from risco.contract.openapi_doc import templates_compatible
from risco.consumers.registry import build_operation_names, detect_generated_dirs
from risco.errors import ScannerUnavailable
from risco.models import Confidence, Strategy

try:
    from tree_sitter import Language, Parser
    import tree_sitter_python as _tsp
    import tree_sitter_typescript as _tst

    PY_LANG = Language(_tsp.language())
    TS_LANG = Language(_tst.language_typescript())
    TREE_SITTER_AVAILABLE = True
except Exception:
    TREE_SITTER_AVAILABLE = False

HTTP_METHODS_TS = {"get", "post", "put", "patch", "delete", "head", "options"}
HTTP_METHODS_PY = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
BASES_TS = {"fetch": "fetch", "axios": "member", "ky": "member", "got": "member"}
PY_MODULE_BASES = {"requests", "httpx", "aiohttp", "httpx_async"}
CLIENT_NAME_RE = re.compile(r"(client|session|http|api)", re.IGNORECASE)

ENV_REGEXES = [
    re.compile(r"os\.environ\.get\(\s*['\"]([\w]+)"),
    re.compile(r"os\.environ\[\s*['\"]([\w]+)"),
    re.compile(r"os\.getenv\(\s*['\"]([\w]+)"),
    re.compile(r"process\.env\.(\w+)"),
    re.compile(r"process\.env\[\s*['\"](\w+)"),
]

INTERP_TYPES = {"interpolation", "template_substitution", "formatted_value"}
STRING_INNER_TYPES = {"string_content", "string_fragment"}

MAX_DYNAMIC_FOR_MATCH = 1


@dataclass
class ScanOutput:
    consumers: list[dict] = field(default_factory=list)
    unresolved: list[dict] = field(default_factory=list)

    def sort(self) -> None:
        self.consumers.sort(key=lambda c: (c["file"], c["line"], c["strategy"], c.get("target_service", "")))
        self.unresolved.sort(key=lambda u: (u["file"], u["line"]))


def _lang_for(path: str) -> str | None:
    lower = path.lower()
    if lower.endswith((".py",)):
        return "python"
    if lower.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        return "typescript"
    return None


def _parser(lang: str):
    if not TREE_SITTER_AVAILABLE:
        raise ScannerUnavailable("tree-sitter grammars not installed")
    p = Parser(PY_LANG if lang == "python" else TS_LANG)
    return p


def extract_env_vars(text: str) -> set[str]:
    out: set[str] = set()
    for rx in ENV_REGEXES:
        out.update(rx.findall(text))
    return out


def extract_string_template(node) -> tuple[str | None, int]:
    parts: list[str] = []
    dynamic = 0
    if node.type in ("string", "template_string"):
        got_inner = False
        for child in node.children:
            if child.type == "," :
                continue
            if child.type in STRING_INNER_TYPES:
                parts.append(child.text.decode("utf-8", "replace"))
                got_inner = True
            elif child.type in INTERP_TYPES:
                parts.append("{*}")
                dynamic += 1
                got_inner = True
        if not got_inner:
            raw = node.text.decode("utf-8", "replace").strip()
            if len(raw) >= 2 and raw[0] in "'\"`" and raw[-1] == raw[0]:
                raw = raw[1:-1]
            parts.append(raw)
        return "".join(parts), dynamic
    if node.type == "string_content":
        return node.text.decode("utf-8", "replace"), 0
    return None, 0


class FileScanner:
    def __init__(self, lang: str, source: bytes):
        self.lang = lang
        self.tree = _parser(lang).parse(source)
        self.assignments: dict[str, object] = {}
        self._collect_assignments()

    def _collect_assignments(self) -> None:
        root = self.tree.root_node

        def walk(n):
            if self.lang == "python" and n.type == "assignment":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left is not None and left.type == "identifier" and right is not None:
                    self.assignments[left.text.decode()] = right
            elif self.lang == "typescript":
                if n.type == "variable_declarator":
                    name = n.child_by_field_name("name")
                    value = n.child_by_field_name("value")
                    if name is not None and value is not None:
                        self.assignments[name.text.decode()] = value
            for c in n.children:
                walk(c)

        walk(root)

    def resolve_expr(self, node, depth: int = 0) -> tuple[str | None, set[str], int]:
        if depth > 4 or node is None:
            return None, set(), 0
        envs = extract_env_vars(node.text.decode("utf-8", "replace"))
        if node.type == "identifier":
            target = self.assignments.get(node.text.decode())
            if target is not None and target is not node:
                tpl, e2, d2 = self.resolve_expr(target, depth + 1)
                return tpl, e2 | envs, d2
            return None, envs, 0
        if node.type in ("string", "template_string"):
            tpl, envs2, dyn = self._string_template(node, depth)
            return tpl, envs | envs2, dyn
        if node.type in ("binary_expression", "binary_operator") and self.lang == "python":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            lt, le, ld = self.resolve_expr(left, depth + 1)
            rt, re_, rd = self.resolve_expr(right, depth + 1)
            envs |= le | re_
            if lt is None and rt is None:
                return None, envs, max(ld, rd) + 1
            if lt is None and le:
                return rt, envs, rd
            if lt is None or rt is None:
                return None, envs, max(ld, rd) + 1
            merged = (lt.rstrip("/") + rt).strip()
            return (merged if merged.startswith("/") else "/" + merged.lstrip("/")), envs, ld + rd
        if node.type == "parenthesized_expression":
            inner = node.named_children[0] if node.named_children else None
            return self.resolve_expr(inner, depth + 1)
        return None, envs, 1

    def _string_template(self, node, depth: int) -> tuple[str | None, set[str], int]:
        parts: list[str] = []
        envs: set[str] = set()
        dyn = 0
        saw_structured = False
        for child in node.children:
            if child.type in STRING_INNER_TYPES:
                raw = child.text.decode("utf-8", "replace")
                if raw.startswith(("'", '"')):
                    continue
                parts.append(raw)
                saw_structured = True
            elif child.type in INTERP_TYPES:
                saw_structured = True
                expr = _interp_expression(child)
                tpl2, envs2, dyn2 = self.resolve_expr(expr, depth + 1) if expr is not None else (None, set(), 1)
                envs |= envs2
                if tpl2 is None:
                    if envs2:
                        parts.append("")
                    else:
                        parts.append("{*}")
                        dyn += 1
                    continue
                tpl2 = _strip_host(tpl2)
                parts.append(tpl2)
                dyn += dyn2
            elif child.type == "escape_sequence":
                continue
            elif child.type == ",":
                continue
        if not saw_structured:
            raw = node.text.decode("utf-8", "replace").strip()
            if len(raw) >= 2 and raw[0] in "'\"`" and raw[-1] == raw[0]:
                raw = raw[1:-1]
            return (raw if raw.startswith("/") or raw.startswith("http") else "/" + raw.lstrip("/")), envs, 0
        merged = "".join(parts)
        merged = _strip_host(merged)
        if not merged.startswith("/"):
            merged = "/" + merged.lstrip("/")
        return merged, envs, dyn


def _ts_call_facts(call_node):
    fn = call_node.child_by_field_name("function")
    args = call_node.child_by_field_name("arguments")
    if fn is None or args is None:
        return None
    fn_text = fn.text.decode("utf-8", "replace")
    url_arg = args.named_children[0] if args.named_children else None
    method = None
    if fn.type == "identifier":
        base, attr = fn_text, ""
    elif fn.type == "member_expression":
        attr_node = fn.child_by_field_name("property")
        obj_node = fn.child_by_field_name("object")
        attr = attr_node.text.decode() if attr_node is not None else ""
        base = obj_node.text.decode() if obj_node is not None else ""
    else:
        return None
    if base == "fetch":
        method = _ts_options_method(
            next((o for o in args.named_children[1:] if o.type == "object"), None)
        )
        if method is None and fn.type == "member_expression":
            attr_node = fn.child_by_field_name("property")
            if attr_node is not None:
                method = attr_node.text.decode().upper()
    elif attr.lower() in HTTP_METHODS_TS and base in ("axios", "ky", "got"):
        method = attr.upper()
        if base in ("ky", "got") and url_arg is not None:
            pass
    elif attr.lower() in HTTP_METHODS_TS and CLIENT_NAME_RE.search(base):
        method = attr.upper()
    else:
        return None
    if url_arg is None:
        return None
    opts_method = None
    for obj in args.named_children[1:]:
        opts_method = _ts_options_method(obj)
        if opts_method:
            break
    if base in ("ky", "got") and opts_method:
        method = opts_method
    return url_arg, (method.upper() if method else None)


def _ts_options_method(obj) -> str | None:
    if obj is None or obj.type != "object":
        return None
    for pair in obj.named_children:
        if pair.type != "pair":
            continue
        key = pair.child_by_field_name("key")
        val = pair.child_by_field_name("value")
        if key is None or val is None:
            continue
        if key.text.decode().strip("'\"") == "method" and val.type == "string":
            v = val.text.decode().strip("'\"")
            if v:
                return v.upper()
    return None


def _py_call_facts(call_node):
    fn = call_node.child_by_field_name("function")
    args = call_node.child_by_field_name("arguments")
    if fn is None or args is None:
        return None
    url_arg = args.named_children[0] if args.named_children else None
    if url_arg is None:
        return None
    if fn.type == "attribute":
        attr_node = None
        for ch in reversed(fn.children):
            if ch.type == "identifier":
                attr_node = ch
                break
        obj_node = fn.child_by_field_name("object")
        if obj_node is None and len(fn.named_children) >= 1:
            obj_node = fn.named_children[0]
        attr = attr_node.text.decode() if attr_node is not None else ""
        base_txt = obj_node.text.decode() if obj_node is not None else ""
        short_base = base_txt.rsplit(".", 1)[-1]
        if attr.lower() in HTTP_METHODS_PY:
            if short_base in PY_MODULE_BASES or CLIENT_NAME_RE.search(short_base):
                return url_arg, attr.upper()
    return None


def _interp_expression(node):
    named = [c for c in node.named_children if c.type not in ("{", "}")]
    if not named:
        return None
    expr = named[0]
    while expr is not None and expr.type in ("parenthesized_expression", "await"):
        inner = [c for c in expr.named_children]
        expr = inner[0] if inner else None
    return expr


_HOST_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+")


def _strip_host(tpl: str | None) -> str | None:
    if tpl is None:
        return None
    m = _HOST_RE.match(tpl)
    if m:
        rest = tpl[m.end():]
        return "/" + rest.lstrip("/")
    return tpl


def _fragment_key(template: str):
    segs = [("*" if re.fullmatch(r"\{[^}/]+\}", s) else s) for s in template.strip("/").split("/")]
    if len(segs) < 2:
        return tuple(segs)
    return tuple(segs[-2:])


def _fragments_equal(a: tuple, b: tuple) -> bool:
    return len(a) == len(b) and all(x == y or x == "*" or y == "*" for x, y in zip(a, b))


def scan_file(
    repo: str,
    path: str,
    text: str,
    registry_rows: list[dict],
    proto_rows: list[dict],
    base_url_env_index: dict[str, str],
    generated_dirs: set[str],
    op_names: dict[str, dict],
    gen_symbols: dict[str, dict] | None = None,
) -> ScanOutput:
    lang = _lang_for(path)
    if lang is None:
        return ScanOutput()
    fs = FileScanner(lang, text.encode())
    out = ScanOutput()
    gen_symbols = gen_symbols or {}

    def walk(n):
        if n.type == "call" or n.type == "call_expression":
            if handle_gen_symbol(n) or handle_call(n):
                pass
        for c in n.children:
            walk(c)

    def handle_gen_symbol(call_node) -> bool:
        if not gen_symbols:
            return False
        fn = call_node.child_by_field_name("function")
        if fn is None:
            return False
        fn_text = fn.text.decode("utf-8", "replace")
        short = fn_text.rsplit(".", 1)[-1]
        if short not in gen_symbols:
            return False
        line = (call_node.start_point[0] + 1) if hasattr(call_node, "start_point") else 1
        out.consumers.append(
            _row(repo, path, line, Strategy.S1_GENERATED_CLIENT, Confidence.HIGH, gen_symbols[short])
        )
        return True

    def handle_call(call_node):
        facts = _py_call_facts(call_node) if lang == "python" else _ts_call_facts(call_node)
        if facts is None:
            return
        url_arg, method = facts
        line = (call_node.start_point[0] + 1) if hasattr(call_node, "start_point") else 1
        tpl, envs, dyn = fs.resolve_expr(url_arg)
        bound_service = None
        for ev in sorted(envs):
            svc = base_url_env_index.get(ev)
            if svc:
                bound_service = svc
                break
        fn_text = call_node.child_by_field_name("function").text.decode()

        if tpl is None:
            if bound_service or dyn >= 1 or envs:
                out.unresolved.append(
                    {
                        "consumer_repo": repo,
                        "consumer_service": "",
                        "file": path,
                        "line": line,
                        "hint_service": bound_service or "",
                        "reason": "nonliteral_url",
                    }
                )
            return

        dynamic_count = tpl.count("{*}")
        if dynamic_count >= 2:
            out.unresolved.append(
                {
                    "consumer_repo": repo,
                    "consumer_service": "",
                    "file": path,
                    "line": line,
                    "hint_service": bound_service or "",
                    "reason": "dynamic_url",
                }
            )
            return

        gen_hit = _generated_client_match(path, fn_text, generated_dirs, op_names)
        candidates = []
        for row in registry_rows:
            if not templates_compatible(tpl, row["path_template"]):
                continue
            if method and row["method"].upper() != method.upper():
                continue
            if bound_service and row["service"] != bound_service:
                continue
            candidates.append(row)
        proto_candidates = []
        for row in proto_rows:
            if bound_service and row["service"] != bound_service:
                continue
            proto_candidates.append(row)

        if gen_hit is not None and not candidates:
            opinfo = op_names[gen_hit]
            out.consumers.append(
                _row(repo, path, line, Strategy.S1_GENERATED_CLIENT, Confidence.HIGH, opinfo)
            )
            return

        if candidates:
            best = sorted(
                candidates,
                key=lambda r: (-int(r.get("specificity", 0)), r["path_template"].count("{"), r["service"], r["path_template"], r["method"]),
            )[0]
            strategy = Strategy.S2_LITERAL_WITH_METHOD if method else Strategy.S3_LITERAL_PATH
            conf = Confidence.HIGH if method else Confidence.MEDIUM
            if bound_service:
                strategy = Strategy.S5_BASE_URL if strategy == Strategy.S3_LITERAL_PATH else strategy
                conf = Confidence.HIGH
            out.consumers.append(
                _row(
                    repo,
                    path,
                    line,
                    strategy,
                    conf,
                    {
                        "operation_id": best.get("operation_id") or "",
                        "service": best["service"],
                        "method": best["method"],
                        "path_template": best["path_template"],
                    },
                )
            )
            return

        if proto_candidates and bound_service:
            best = sorted(proto_candidates, key=lambda r: (r["service"], r["rpc"]))[0]
            out.consumers.append(
                _row(
                    repo,
                    path,
                    line,
                    Strategy.S1_GENERATED_CLIENT,
                    Confidence.MEDIUM,
                    {
                        "operation_id": "",
                        "service": best["service"],
                        "method": "",
                        "path_template": "",
                        "rpc": best["rpc"],
                    },
                )
            )
            return

        frag = _fragment_key(tpl)
        frag_rows = [
            r
            for r in registry_rows
            if _fragments_equal(_fragment_key(r["path_template"]), frag) and (not bound_service or r["service"] == bound_service)
        ]
        if frag_rows and dynamic_count <= MAX_DYNAMIC_FOR_MATCH:
            best = sorted(frag_rows, key=lambda r: (r["path_template"], r["service"]))[0]
            conf = Confidence.LOW
            strategy = Strategy.S4_FRAGMENT
            if bound_service:
                strategy = Strategy.S5_BASE_URL
                conf = Confidence.MEDIUM
            out.consumers.append(
                _row(
                    repo,
                    path,
                    line,
                    strategy,
                    conf,
                    {
                        "operation_id": best.get("operation_id") or "",
                        "service": best["service"],
                        "method": best["method"],
                        "path_template": best["path_template"],
                    },
                )
            )
            return

        if bound_service:
            out.unresolved.append(
                {
                    "consumer_repo": repo,
                    "consumer_service": "",
                    "file": path,
                    "line": line,
                    "hint_service": bound_service,
                    "reason": "bound_no_match",
                }
            )

    walk(fs.tree.root_node)
    out.sort()
    return out


def _generated_client_match(path: str, fn_text: str, generated_dirs: set[str], op_names: dict[str, dict]) -> str | None:
    if not generated_dirs:
        return None
    under = any(path.startswith(d) for d in generated_dirs)
    if not under:
        return None
    short = fn_text.rsplit(".", 1)[-1]
    if short in op_names:
        return short
    return None


def _row(repo: str, path: str, line: int, strategy: Strategy, conf: Confidence, info: dict) -> dict:
    return {
        "consumer_repo": repo,
        "consumer_service": "",
        "file": path,
        "line": line,
        "strategy": strategy.value,
        "confidence": conf.value,
        "method": info.get("method", "") or "",
        "operation_id": info.get("operation_id", "") or "",
        "path_template": info.get("path_template", "") or "",
        "target_service": info.get("service", ""),
    }


def _exported_symbols(text: str) -> set[str]:
    names: set[str] = set()
    for m in re.finditer(
        r"export\s+(?:default\s+)?(?:async\s+)?function\s+(\w+)", text
    ):
        names.add(m.group(1))
    for m in re.finditer(r"export\s+const\s+(\w+)\s*[=:]", text):
        names.add(m.group(1))
    return names


def scan_repo(
    repo: str,
    files: dict[str, str],
    registry_rows: list[dict],
    proto_rows: list[dict],
    base_url_env_index: dict[str, str],
) -> ScanOutput:
    gen_dirs = detect_generated_dirs(sorted(files))
    op_names = build_operation_names(registry_rows)
    gen_symbols: dict[str, dict] = {}
    for path, text in sorted(files.items()):
        under = any(path.startswith(d) for d in gen_dirs)
        if not under:
            continue
        for sym in _exported_symbols(text):
            info = op_names.get(sym)
            if info is not None:
                gen_symbols[sym] = info
    combined = ScanOutput()
    for path in sorted(files):
        res = scan_file(
            repo,
            path,
            files[path],
            registry_rows,
            proto_rows,
            base_url_env_index,
            gen_dirs,
            op_names,
            gen_symbols,
        )
        combined.consumers.extend(res.consumers)
        combined.unresolved.extend(res.unresolved)
    combined.sort()
    return combined
