"""Tests for IOC extraction."""

from soc_chronicle.ioc.engine import IOCExtractionEngine
from soc_chronicle.models.ioc import IOCType


def test_extract_ipv4_and_domain() -> None:
    engine = IOCExtractionEngine()
    text = "Connection to evil-c2[.]example.com from 192.0.2.50"
    iocs = engine.extract_from_texts([text])
    types = {i.type for i in iocs}
    assert IOCType.IPV4 in types
    assert IOCType.DOMAIN in types
    domain = next(i for i in iocs if i.type == IOCType.DOMAIN)
    assert domain.value == "evil-c2.example.com"
    assert domain.defanged is True


def test_extract_hash() -> None:
    engine = IOCExtractionEngine()
    hash_val = "a" * 64
    iocs = engine.extract_from_texts([f"File hash: {hash_val}"])
    assert any(i.type == IOCType.SHA256 and i.value == hash_val for i in iocs)


def test_deduplication() -> None:
    engine = IOCExtractionEngine()
    iocs = engine.extract_from_texts(["192.0.2.50 seen twice 192.0.2.50"])
    ipv4 = [i for i in iocs if i.type == IOCType.IPV4]
    assert len(ipv4) == 1
