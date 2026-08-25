from __future__ import annotations

from dataclasses import dataclass, field

from risco.contract.openapi_doc import (
    iter_operations,
    load_openapi_text,
    proto_package,
    proto_services,
    template_specificity,
    template_to_regex,
)


@dataclass
class RegistryBuild:
    registry: list[dict] = field(default_factory=list)
    registry_proto: list[dict] = field(default_factory=list)

    def merge(self, other: "RegistryBuild") -> None:
        self.registry.extend(other.registry)
        self.registry_proto.extend(other.registry_proto)


def service_identity(manifested: bool, svc_name: str, repo_name: str) -> str:
    return svc_name.strip() if (manifested and svc_name.strip()) else repo_name


def build_registry_from_openapi(
    service: str,
    repo: str,
    file_path: str,
    text: str,
) -> RegistryBuild:
    out = RegistryBuild()
    try:
        doc = load_openapi_text(text, file_path)
    except Exception:
        return out
    for op in iter_operations(doc):
        template = op["path_template"]
        out.registry.append(
            {
                "service": service,
                "method": op["method"],
                "path_template": template,
                "path_regex": template_to_regex(template).pattern,
                "specificity": template_specificity(template),
                "operation_id": op["operation_id"] or "",
                "source_repo": repo,
                "source_file": file_path,
            }
        )
    return out


def build_registry_from_proto(
    service: str,
    repo: str,
    file_path: str,
    text: str,
) -> RegistryBuild:
    out = RegistryBuild()
    package = proto_package(text)
    for svc, rpc in proto_services(text):
        full = f"{package}.{svc}" if package else svc
        out.registry_proto.append(
            {
                "service": full,
                "rpc": rpc,
                "package": package,
                "source_repo": repo,
                "source_file": file_path,
            }
        )
    del service
    return out


GENERATOR_CONFIG_FILES = (
    "orval.config.ts",
    "orval.config.js",
    "openapitools.json",
    ".openapi-generator/config.yaml",
    "openapi-typescript.ts",
    "openapi-typescript.config.ts",
)


def detect_generated_dirs(files: list[str]) -> set[str]:
    dirs: set[str] = set()
    for f in files:
        for cfg in GENERATOR_CONFIG_FILES:
            if f == cfg or f.endswith("/" + cfg):
                parent = f.rsplit("/", 1)[0] if "/" in f else ""
                dirs.add(parent)
    for f in files:
        head = "/".join(f.split("/")[:2])
        if any(f.startswith(p) for p in ("src/gen/", "gen/", "src/generated/", "generated/", "__generated__/")):
            dirs.add(head)
    return {d.strip("/") + "/" for d in dirs if d}


def camel_to_snake(name: str) -> str:
    out = []
    for ch in name:
        if ch.isupper():
            out.append("_")
            out.append(ch.lower())
        else:
            out.append(ch)
    return "".join(out).lstrip("_")


def snake_to_camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def operation_name_variants(op_id: str) -> set[str]:
    variants = {op_id}
    if "_" in op_id:
        variants.add(snake_to_camel(op_id))
    if any(c.isupper() for c in op_id):
        variants.add(camel_to_snake(op_id))
    return {v for v in variants if v}


def build_operation_names(registry_rows: list[dict]) -> dict[str, dict]:
    names: dict[str, dict] = {}
    for row in registry_rows:
        op_id = row.get("operation_id") or ""
        if not op_id:
            continue
        for variant in operation_name_variants(op_id):
            existing = names.get(variant)
            candidate = {
                "operation_id": op_id,
                "service": row["service"],
                "method": row["method"],
                "path_template": row["path_template"],
            }
            if existing is None:
                names[variant] = candidate
            else:
                keep = min(existing, candidate, key=lambda c: (c["service"], c["method"], c["path_template"]))
                names[variant] = keep
    return names
