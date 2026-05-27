import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ghostgraph.certificate import issue_certificate
from ghostgraph.models import RiskAssessment, RiskLevel


def test_certificate_signature_verifies():
    risk = RiskAssessment(score=5, level=RiskLevel.low, reasons=["clean"], score_breakdown={})
    cert = issue_certificate("agent-x", risk, [], [])
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(cert.public_key))
    public_key.verify(base64.b64decode(cert.signature), cert.evidence_hash.encode("utf-8"))
    assert cert.evidence_hash.startswith("sha256:")
    assert cert.certificate_hash.startswith("sha256:")
