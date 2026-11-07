"""Gossip envelope: canonical round-trip + DSM<->Mesh wire compatibility.

These tests pin the on-wire HMAC envelope so DSM gossip and Mesh consciousness
can never silently drift apart (the failure mode that the shared
shared/common/gossip_envelope.py module was introduced to prevent).
"""
import hashlib
import hmac
import json

import pytest

from shared.common.gossip_envelope import sign_envelope, open_envelope


KEY = b"unit-test-mesh-key-0123456789abcd"


@pytest.mark.unit
def test_sign_open_roundtrip():
    body = json.dumps({"hello": "world", "n": 1}, sort_keys=True).encode("utf-8")
    wire = sign_envelope(KEY, body)
    opened = open_envelope(KEY, wire)
    assert opened.is_envelope and opened.verified
    assert opened.body == body


@pytest.mark.unit
def test_canonical_byte_format():
    """Envelope must be exactly {"body": <str>, "mac": <hexdigest>} (no drift)."""
    body = b'{"x":1}'
    wire = sign_envelope(KEY, body)
    obj = json.loads(wire.decode("utf-8"))
    assert set(obj.keys()) == {"body", "mac"}
    assert obj["body"] == body.decode("utf-8")
    assert obj["mac"] == hmac.new(KEY, body, hashlib.sha256).hexdigest()


@pytest.mark.unit
def test_bad_mac_not_verified():
    body = b'{"x":1}'
    opened = open_envelope(b"wrong-key-wrong-key-wrong-key-00", sign_envelope(KEY, body))
    assert opened.is_envelope and not opened.verified


@pytest.mark.unit
def test_non_envelope_detected():
    opened = open_envelope(KEY, b"not json at all")
    assert not opened.is_envelope and opened.body is None
    opened2 = open_envelope(KEY, b'{"some":"json","but":"no mac"}')
    assert not opened2.is_envelope


@pytest.mark.unit
def test_dsm_to_mesh_wire_compat():
    """A DSM GossipMessage signed with mesh_key must verify under mesh's policy."""
    from shared.dsm.gossip import GossipMessage

    msg = GossipMessage(msg_type="announce", source_node="node-a", payload={"b": 1})
    wire = msg.to_bytes(mesh_key=KEY)

    # Mesh-side verify (lenient policy returns the inner body on success).
    opened = open_envelope(KEY, wire)
    assert opened.is_envelope and opened.verified
    # And DSM can read its own message back.
    back = GossipMessage.from_bytes(wire, mesh_key=KEY)
    assert back.msg_type == "announce" and back.source_node == "node-a"


@pytest.mark.unit
def test_mesh_to_dsm_wire_compat():
    """A mesh-signed envelope of a GossipMessage body must parse in DSM.from_bytes."""
    from shared.dsm.gossip import GossipMessage

    inner = json.dumps(
        {
            "msg_type": "checkpoint",
            "source_node": "node-b",
            "payload": {"c": 2},
            "hop_count": 0,
            "seen_by": [],
            "timestamp": 1.0,
        },
        sort_keys=True,
    ).encode("utf-8")
    wire = sign_envelope(KEY, inner)  # mesh _sign_gossip equivalent
    msg = GossipMessage.from_bytes(wire, mesh_key=KEY)
    assert msg.msg_type == "checkpoint" and msg.source_node == "node-b"


@pytest.mark.unit
def test_dsm_strict_policy_rejects_unsigned_and_tampered():
    from shared.dsm.gossip import GossipMessage

    plain = json.dumps(
        {"msg_type": "x", "source_node": "y", "payload": {}}, sort_keys=True
    ).encode("utf-8")
    # Unsigned input with mesh_key set -> strict raise.
    with pytest.raises(ValueError):
        GossipMessage.from_bytes(plain, mesh_key=KEY)
    # Tampered MAC -> raise.
    tampered = sign_envelope(KEY, plain)[:-3] + b'00"'
    with pytest.raises(ValueError):
        GossipMessage.from_bytes(tampered, mesh_key=KEY)
