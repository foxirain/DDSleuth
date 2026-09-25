from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .models import JsonValue, Scenario


class IdentityError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ParticipantIdentity:
    actor: str
    subject_name: str
    certificate: Path
    private_key: Path
    certificate_sha256: str


@dataclass(frozen=True, slots=True)
class IdentityArtifacts:
    ca_certificate: Path
    ca_private_key: Path
    ca_certificate_sha256: str
    participants: Mapping[str, ParticipantIdentity]
    manifest: Path

    @property
    def subject_names(self) -> dict[str, str]:
        return {actor: identity.subject_name for actor, identity in self.participants.items()}

    def evidence_binding(self) -> dict[str, JsonValue]:
        return {
            "identity_ca_certificate_sha256": self.ca_certificate_sha256,
            "identity_certificates": {
                actor: identity.certificate_sha256
                for actor, identity in self.participants.items()
            },
        }

    def role_environments(self) -> dict[str, dict[str, str]]:
        return {
            actor: {
                "DDSLEUTH_IDENTITY_CA": str(self.ca_certificate),
                "DDSLEUTH_IDENTITY_CERTIFICATE": str(identity.certificate),
                "DDSLEUTH_IDENTITY_PRIVATE_KEY": str(identity.private_key),
                "DDSLEUTH_IDENTITY_SUBJECT": identity.subject_name,
            }
            for actor, identity in self.participants.items()
        }


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], context: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as error:
        raise IdentityError("openssl executable is required") from error
    except subprocess.CalledProcessError as error:
        message = error.stderr.strip() or error.stdout.strip() or f"exit {error.returncode}"
        raise IdentityError(f"{context}: {message}") from error


def _safe_actor_name(actor: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", actor).strip("-")
    if not slug:
        raise IdentityError(f"actor name {actor!r} has no safe filename representation")
    return slug


def _subject(certificate: Path) -> str:
    completed = _run(
        [
            "openssl",
            "x509",
            "-in",
            str(certificate),
            "-noout",
            "-subject",
            "-nameopt",
            "RFC2253",
        ],
        f"cannot read certificate subject from {certificate.name}",
    )
    subject = completed.stdout.strip()
    if subject.startswith("subject="):
        subject = subject.removeprefix("subject=")
    if not subject:
        raise IdentityError(f"certificate {certificate.name} has no subject")
    return subject


def _generate_ec_key(path: Path) -> None:
    _run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            str(path),
        ],
        f"cannot generate {path.name}",
    )
    os.chmod(path, 0o600)


def _validate_subject(subject: str, context: str) -> None:
    if not subject.startswith("/") or any(character in subject for character in ("\x00", "\n", "\r")):
        raise IdentityError(f"{context} must be an OpenSSL slash-form subject without control characters")


def materialize_identities(
    scenario: Scenario,
    output_dir: Path,
    *,
    ca_subject: str = "/CN=DDSleuth Ephemeral Identity CA",
    validity_days: int = 7,
    overwrite: bool = False,
) -> IdentityArtifacts:
    if validity_days <= 0:
        raise IdentityError("identity validity_days must be positive")
    _validate_subject(ca_subject, "identity CA subject")
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = output_dir / "identity-binding.json"
    if any(output_dir.iterdir()) and not overwrite:
        raise IdentityError(f"identity output directory is not empty: {output_dir}")

    ca_key = output_dir / "identity-ca.key"
    ca_certificate = output_dir / "identity-ca.cert.pem"
    _generate_ec_key(ca_key)
    _run(
        [
            "openssl",
            "req",
            "-x509",
            "-new",
            "-key",
            str(ca_key),
            "-sha256",
            "-days",
            str(validity_days),
            "-subj",
            ca_subject,
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
            "-out",
            str(ca_certificate),
        ],
        "cannot generate identity CA certificate",
    )

    identities: dict[str, ParticipantIdentity] = {}
    expiring = any(
        participant.identity is not None
        and participant.identity.expires_after_seconds is not None
        for participant in scenario.participants.values()
    )
    ca_config = output_dir / "openssl-ca.cnf"
    if expiring:
        (output_dir / "newcerts").mkdir(exist_ok=True)
        (output_dir / "index.txt").write_text("", encoding="utf-8")
        (output_dir / "serial").write_text("1000\n", encoding="utf-8")
        ca_config.write_text(
            "[ca]\n"
            "default_ca=dds_ca\n"
            "[dds_ca]\n"
            f"database={output_dir / 'index.txt'}\n"
            f"new_certs_dir={output_dir / 'newcerts'}\n"
            f"certificate={ca_certificate}\n"
            f"private_key={ca_key}\n"
            f"serial={output_dir / 'serial'}\n"
            "default_md=sha256\n"
            "default_days=7\n"
            "policy=dds_policy\n"
            "unique_subject=no\n"
            "copy_extensions=copy\n"
            "[dds_policy]\n"
            "countryName=optional\n"
            "stateOrProvinceName=optional\n"
            "localityName=optional\n"
            "organizationName=optional\n"
            "organizationalUnitName=optional\n"
            "commonName=supplied\n"
            "emailAddress=optional\n",
            encoding="utf-8",
        )
    filenames: set[str] = set()
    for index, (actor, participant) in enumerate(scenario.participants.items(), start=2):
        filename = _safe_actor_name(actor)
        if filename in filenames:
            raise IdentityError("participant names collide after filename normalization")
        filenames.add(filename)
        if participant.identity is None:
            raise IdentityError(f"participant {actor!r} does not declare identity.subject")
        requested_subject = participant.identity.subject
        _validate_subject(requested_subject, f"identity subject for {actor}")
        key = output_dir / f"{filename}.key"
        csr = output_dir / f"{filename}.csr"
        certificate = output_dir / f"{filename}.cert.pem"
        extensions = output_dir / f"{filename}.ext"
        extensions.write_text(
            "[usr_cert]\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyAgreement\n",
            encoding="utf-8",
        )
        _generate_ec_key(key)
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(key),
                "-subj",
                requested_subject,
                "-out",
                str(csr),
            ],
            f"cannot generate identity request for {actor}",
        )
        expires_after = participant.identity.expires_after_seconds
        if expires_after is None:
            signing_command = [
                "openssl", "x509", "-req", "-in", str(csr),
                "-CA", str(ca_certificate), "-CAkey", str(ca_key),
                "-set_serial", str(index), "-days", str(validity_days),
                "-sha256", "-extfile", str(extensions), "-extensions", "usr_cert",
                "-out", str(certificate),
            ]
        else:
            now = datetime.now(timezone.utc)
            start = (now - timedelta(seconds=30)).strftime("%Y%m%d%H%M%SZ")
            end = (now + timedelta(seconds=expires_after)).strftime("%Y%m%d%H%M%SZ")
            signing_command = [
                "openssl", "ca", "-batch", "-notext", "-config", str(ca_config),
                "-in", str(csr), "-startdate", start, "-enddate", end,
                "-extfile", str(extensions), "-extensions", "usr_cert",
                "-out", str(certificate),
            ]
        _run(signing_command, f"cannot sign identity certificate for {actor}")
        _run(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(ca_certificate),
                str(certificate),
            ],
            f"cannot verify identity certificate for {actor}",
        )
        identities[actor] = ParticipantIdentity(
            actor=actor,
            subject_name=_subject(certificate),
            certificate=certificate,
            private_key=key,
            certificate_sha256=_digest(certificate),
        )

    artifacts = IdentityArtifacts(
        ca_certificate=ca_certificate,
        ca_private_key=ca_key,
        ca_certificate_sha256=_digest(ca_certificate),
        participants=identities,
        manifest=manifest,
    )
    manifest_value: dict[str, JsonValue] = {
        "schema_version": 1,
        "scenario_digest": scenario.digest,
        **artifacts.evidence_binding(),
        "identity_ca_certificate_file": ca_certificate.name,
        "identity_certificate_files": {
            actor: identity.certificate.name
            for actor, identity in identities.items()
        },
        "subjects": artifacts.subject_names,
        "expires_after_seconds": {
            actor: identity.expires_after_seconds
            for actor, participant in scenario.participants.items()
            if (identity := participant.identity) is not None
            and identity.expires_after_seconds is not None
        },
    }
    manifest.write_text(
        json.dumps(manifest_value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return artifacts
