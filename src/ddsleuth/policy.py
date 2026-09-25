from __future__ import annotations

import hashlib
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .models import JsonValue, Scenario


XSI = "http://www.w3.org/2001/XMLSchema-instance"
ET.register_namespace("xsi", XSI)

_DOMAIN_PROTECTION = {"NONE", "SIGN", "ENCRYPT"}
_METADATA_PROTECTION = {
    "NONE",
    "SIGN",
    "ENCRYPT",
    "SIGN_WITH_ORIGIN_AUTHENTICATION",
    "ENCRYPT_WITH_ORIGIN_AUTHENTICATION",
}
_DATA_PROTECTION = {"NONE", "SIGN", "ENCRYPT"}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PolicyArtifacts:
    governance_xml: Path
    permissions_xml: Path
    governance_smime: Path | None
    permissions_smime: Path | None
    digests: Mapping[str, str]


def _bool(value: JsonValue | None, default: bool) -> str:
    selected = default if value is None else value
    if not isinstance(selected, bool):
        raise PolicyError(f"expected boolean governance value, got {selected!r}")
    return "true" if selected else "false"


def _protection(value: JsonValue | None, default: str, allowed: set[str], context: str) -> str:
    selected = default if value is None else value
    if not isinstance(selected, str):
        raise PolicyError(f"{context} protection must be a string")
    normalized = selected.upper()
    if normalized not in allowed:
        raise PolicyError(f"unsupported {context} protection kind: {selected!r}")
    return normalized


def _text(parent: ET.Element, name: str, value: object) -> ET.Element:
    element = ET.SubElement(parent, name)
    element.text = str(value)
    return element


def _root(schema_name: str) -> ET.Element:
    return ET.Element(
        "dds",
        {f"{{{XSI}}}noNamespaceSchemaLocation": schema_name},
    )


def governance_tree(scenario: Scenario) -> ET.ElementTree:
    root = _root("omg_shared_ca_domain_governance.xsd")
    access_rules = ET.SubElement(root, "domain_access_rules")
    domain_rule = ET.SubElement(access_rules, "domain_rule")
    domains = ET.SubElement(domain_rule, "domains")
    _text(domains, "id", scenario.domain_id)

    governance = scenario.governance
    _text(
        domain_rule,
        "allow_unauthenticated_participants",
        _bool(governance.get("allow_unauthenticated_participants"), False),
    )
    _text(
        domain_rule,
        "enable_join_access_control",
        _bool(governance.get("enable_join_access_control"), True),
    )
    _text(
        domain_rule,
        "discovery_protection_kind",
        _protection(
            governance.get("discovery_protection"),
            "ENCRYPT",
            _DOMAIN_PROTECTION,
            "discovery",
        ),
    )
    _text(
        domain_rule,
        "liveliness_protection_kind",
        _protection(
            governance.get("liveliness_protection"),
            "ENCRYPT",
            _DOMAIN_PROTECTION,
            "liveliness",
        ),
    )
    _text(
        domain_rule,
        "rtps_protection_kind",
        _protection(
            governance.get("rtps_protection"),
            "ENCRYPT",
            _DOMAIN_PROTECTION,
            "rtps",
        ),
    )

    topic_access_rules = ET.SubElement(domain_rule, "topic_access_rules")
    for topic_name, topic in scenario.topics.items():
        topic_rule = ET.SubElement(topic_access_rules, "topic_rule")
        _text(topic_rule, "topic_expression", topic_name)
        _text(
            topic_rule,
            "enable_discovery_protection",
            _bool(topic.get("enable_discovery_protection"), True),
        )
        _text(
            topic_rule,
            "enable_liveliness_protection",
            _bool(topic.get("enable_liveliness_protection"), True),
        )
        _text(
            topic_rule,
            "enable_read_access_control",
            _bool(topic.get("enable_read_access_control"), True),
        )
        _text(
            topic_rule,
            "enable_write_access_control",
            _bool(topic.get("enable_write_access_control"), True),
        )
        _text(
            topic_rule,
            "metadata_protection_kind",
            _protection(
                topic.get("metadata_protection"),
                "ENCRYPT_WITH_ORIGIN_AUTHENTICATION",
                _METADATA_PROTECTION,
                f"topic {topic_name} metadata",
            ),
        )
        _text(
            topic_rule,
            "data_protection_kind",
            _protection(
                topic.get("data_protection"),
                "ENCRYPT",
                _DATA_PROTECTION,
                f"topic {topic_name} data",
            ),
        )

    ET.indent(root, space="  ")
    return ET.ElementTree(root)


def _grant_name(actor: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", actor)
    return "".join(word[:1].upper() + word[1:] for word in words) or "Participant"


def permissions_tree(
    scenario: Scenario,
    subject_names: Mapping[str, str],
    *,
    not_before: str,
    not_after: str,
) -> ET.ElementTree:
    missing = sorted(set(scenario.participants) - set(subject_names))
    extra = sorted(set(subject_names) - set(scenario.participants))
    if missing:
        raise PolicyError(f"missing subject names for: {', '.join(missing)}")
    if extra:
        raise PolicyError(f"subject names provided for unknown actors: {', '.join(extra)}")

    root = _root("omg_shared_ca_permissions.xsd")
    permissions = ET.SubElement(root, "permissions")
    for actor in scenario.grant_order:
        participant = scenario.participants[actor]
        grant = ET.SubElement(permissions, "grant", {"name": _grant_name(actor)})
        _text(grant, "subject_name", subject_names[actor])
        validity = ET.SubElement(grant, "validity")
        _text(validity, "not_before", not_before)
        _text(validity, "not_after", not_after)
        allow_rule = ET.SubElement(grant, "allow_rule")
        domains = ET.SubElement(allow_rule, "domains")
        _text(domains, "id", scenario.domain_id)

        publish = participant.permissions.get("publish", ())
        if publish:
            publish_element = ET.SubElement(allow_rule, "publish")
            topics = ET.SubElement(publish_element, "topics")
            for topic in publish:
                _text(topics, "topic", topic)

        subscribe = participant.permissions.get("subscribe", ())
        if subscribe:
            subscribe_element = ET.SubElement(allow_rule, "subscribe")
            topics = ET.SubElement(subscribe_element, "topics")
            for topic in subscribe:
                _text(topics, "topic", topic)

        _text(grant, "default", "DENY")

    ET.indent(root, space="  ")
    return ET.ElementTree(root)


def _write_tree(tree: ET.ElementTree, path: Path) -> None:
    tree.write(path, encoding="utf-8", xml_declaration=True, short_empty_elements=False)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sign(xml_path: Path, output_path: Path, signer_cert: Path, signer_key: Path) -> None:
    subprocess.run(
        [
            "openssl",
            "smime",
            "-sign",
            "-in",
            str(xml_path),
            "-text",
            "-out",
            str(output_path),
            "-signer",
            str(signer_cert),
            "-inkey",
            str(signer_key),
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        [
            "openssl",
            "smime",
            "-verify",
            "-CAfile",
            str(signer_cert),
            "-in",
            str(output_path),
            "-out",
            "/dev/null",
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def materialize_policies(
    scenario: Scenario,
    output_dir: Path,
    subject_names: Mapping[str, str],
    *,
    not_before: str = "2020-01-01T00:00:00",
    not_after: str = "2038-01-01T00:00:00",
    signer_cert: Path | None = None,
    signer_key: Path | None = None,
    overwrite: bool = False,
) -> PolicyArtifacts:
    if (signer_cert is None) != (signer_key is None):
        raise PolicyError("signer_cert and signer_key must be supplied together")
    output_dir.mkdir(parents=True, exist_ok=True)
    governance_xml = output_dir / "governance.xml"
    permissions_xml = output_dir / "permissions.xml"
    governance_smime = output_dir / "governance.smime" if signer_cert else None
    permissions_smime = output_dir / "permissions.smime" if signer_cert else None
    outputs = [governance_xml, permissions_xml]
    outputs.extend(path for path in (governance_smime, permissions_smime) if path is not None)
    existing = [path for path in outputs if path.exists()]
    if existing and not overwrite:
        raise PolicyError(f"policy output already exists: {existing[0]}")

    _write_tree(governance_tree(scenario), governance_xml)
    _write_tree(
        permissions_tree(
            scenario,
            subject_names,
            not_before=not_before,
            not_after=not_after,
        ),
        permissions_xml,
    )

    if signer_cert and signer_key and governance_smime and permissions_smime:
        _sign(governance_xml, governance_smime, signer_cert, signer_key)
        _sign(permissions_xml, permissions_smime, signer_cert, signer_key)

    return PolicyArtifacts(
        governance_xml=governance_xml,
        permissions_xml=permissions_xml,
        governance_smime=governance_smime,
        permissions_smime=permissions_smime,
        digests={path.name: _digest(path) for path in outputs},
    )
