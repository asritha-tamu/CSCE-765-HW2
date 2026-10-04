import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa

from handshake import (
    make_transcript,
    sha256,
    sign,
    verify,
    check_transcript,
    GATEWAY_ROLE,
    NODE_ROLE,
    GATEWAY_ID,
    NODE_ID,
    PROTOCOL,
    GROUP,
    field,
)

from secure_record import (
    seal,
    open_record,
    GATEWAY_TO_NODE,
    NODE_TO_GATEWAY,
    HEADER_SIZE,
    IV_SIZE,
)


# --------------------------------------------------
# Test setup: keys, transcript, and record-layer keys
# --------------------------------------------------

@pytest.fixture
def handshake_setup():
    gateway_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    node_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    # Fixed-length values for testing transcript encoding.
    gateway_public_value = b"G" * 384
    node_public_value = b"N" * 384
    gateway_nonce = b"g" * 16
    node_nonce = b"n" * 16

    transcript = make_transcript(
        gateway_public_value,
        node_public_value,
        gateway_nonce,
        node_nonce,
    )

    transcript_hash = sha256(transcript)

    gateway_signature = sign(
        gateway_private, GATEWAY_ROLE, transcript_hash
    )
    node_signature = sign(
        node_private, NODE_ROLE, transcript_hash
    )

    return {
        "gateway_private": gateway_private,
        "node_private": node_private,
        "transcript": transcript,
        "transcript_hash": transcript_hash,
        "gateway_signature": gateway_signature,
        "node_signature": node_signature,
    }


@pytest.fixture
def record_keys():
    return {
        "g2n_enc": b"A" * 32,
        "g2n_mac": b"B" * 32,
        "n2g_enc": b"C" * 32,
        "n2g_mac": b"D" * 32,
        "session_id": b"12345678",
    }


# --------------------------------------------------
# 1. Valid handshake and bidirectional messages
# --------------------------------------------------

def test_valid_handshake_and_bidirectional_messages(
    handshake_setup, record_keys
):
    hs = handshake_setup
    keys = record_keys

    # Both parties accept the same transcript.
    fields = check_transcript(hs["transcript"])
    assert fields[0] == PROTOCOL
    assert fields[1] == GROUP
    assert fields[2] == GATEWAY_ID
    assert fields[3] == NODE_ID

    # Both transcript signatures verify.
    verify(
        hs["gateway_private"].public_key(),
        GATEWAY_ROLE,
        hs["transcript_hash"],
        hs["gateway_signature"],
    )
    verify(
        hs["node_private"].public_key(),
        NODE_ROLE,
        hs["transcript_hash"],
        hs["node_signature"],
    )

    # Gateway sends to node using gateway-to-node keys.
    g2n_record = seal(
        keys["g2n_enc"],
        keys["g2n_mac"],
        keys["session_id"],
        0,
        GATEWAY_TO_NODE,
        1,
        b"Hello node",
    )

    node_plaintext = open_record(
        keys["g2n_enc"],
        keys["g2n_mac"],
        keys["session_id"],
        0,
        GATEWAY_TO_NODE,
        g2n_record,
    )
    assert node_plaintext == b"Hello node"

    # Node sends to gateway using separate node-to-gateway keys.
    n2g_record = seal(
        keys["n2g_enc"],
        keys["n2g_mac"],
        keys["session_id"],
        0,
        NODE_TO_GATEWAY,
        1,
        b"Hello gateway",
    )

    gateway_plaintext = open_record(
        keys["n2g_enc"],
        keys["n2g_mac"],
        keys["session_id"],
        0,
        NODE_TO_GATEWAY,
        n2g_record,
    )
    assert gateway_plaintext == b"Hello gateway"


# --------------------------------------------------
# 2. Modified ciphertext
# --------------------------------------------------

def test_modified_ciphertext_is_rejected(record_keys):
    keys = record_keys

    record = seal(
        keys["g2n_enc"], keys["g2n_mac"], keys["session_id"],
        0, GATEWAY_TO_NODE, 1, b"Secret message"
    )

    modified = bytearray(record)
    ciphertext_position = HEADER_SIZE + IV_SIZE
    modified[ciphertext_position] ^= 1

    # HMAC verification must fail before decryption.
    with pytest.raises(InvalidSignature):
        open_record(
            keys["g2n_enc"], keys["g2n_mac"], keys["session_id"],
            0, GATEWAY_TO_NODE, bytes(modified)
        )


# --------------------------------------------------
# 3. Modified authenticated header
# --------------------------------------------------

def test_modified_authenticated_header_is_rejected(record_keys):
    keys = record_keys

    record = seal(
        keys["g2n_enc"], keys["g2n_mac"], keys["session_id"],
        0, GATEWAY_TO_NODE, 1, b"Secret message"
    )

    modified = bytearray(record)

    # Byte 10 is message_type. Change it without changing the tag.
    modified[10] ^= 1

    # The changed header must fail HMAC verification.
    with pytest.raises(InvalidSignature):
        open_record(
            keys["g2n_enc"], keys["g2n_mac"], keys["session_id"],
            0, GATEWAY_TO_NODE, bytes(modified)
        )


# --------------------------------------------------
# 4. Replayed record
# --------------------------------------------------

def test_replayed_record_is_rejected(record_keys):
    keys = record_keys

    record = seal(
        keys["g2n_enc"], keys["g2n_mac"], keys["session_id"],
        0, GATEWAY_TO_NODE, 1, b"First message"
    )

    # The first record is accepted with expected sequence 0.
    assert open_record(
        keys["g2n_enc"], keys["g2n_mac"], keys["session_id"],
        0, GATEWAY_TO_NODE, record
    ) == b"First message"

    # The receiver now expects sequence 1. Replaying sequence 0 fails.
    with pytest.raises(ValueError, match="Unexpected sequence number"):
        open_record(
            keys["g2n_enc"], keys["g2n_mac"], keys["session_id"],
            1, GATEWAY_TO_NODE, record
        )


# --------------------------------------------------
# 5. Record reflected into the opposite direction
# --------------------------------------------------

def test_record_reflected_into_opposite_direction_is_rejected(
    record_keys
):
    keys = record_keys

    record = seal(
        keys["g2n_enc"], keys["g2n_mac"], keys["session_id"],
        0, GATEWAY_TO_NODE, 1, b"Gateway to node"
    )

    # Try to deliver a gateway-to-node record as node-to-gateway.
    with pytest.raises(ValueError, match="Wrong message direction"):
        open_record(
            keys["n2g_enc"], keys["n2g_mac"], keys["session_id"],
            0, NODE_TO_GATEWAY, record
        )


# --------------------------------------------------
# 6. Incorrect RSA public key
# --------------------------------------------------

def test_incorrect_rsa_public_key_is_rejected(handshake_setup):
    hs = handshake_setup

    incorrect_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    # A different public key must not verify the gateway's signature.
    with pytest.raises(ValueError, match="Invalid RSA-PSS signature"):
        verify(
            incorrect_private.public_key(),
            GATEWAY_ROLE,
            hs["transcript_hash"],
            hs["gateway_signature"],
        )


# --------------------------------------------------
# 7. Invalid RSA-PSS transcript signature
# --------------------------------------------------

def test_invalid_transcript_signature_is_rejected(handshake_setup):
    hs = handshake_setup

    bad_signature = bytearray(hs["gateway_signature"])
    bad_signature[0] ^= 1

    with pytest.raises(ValueError, match="Invalid RSA-PSS signature"):
        verify(
            hs["gateway_private"].public_key(),
            GATEWAY_ROLE,
            hs["transcript_hash"],
            bytes(bad_signature),
        )


# --------------------------------------------------
# 8. Reflected handshake message
# --------------------------------------------------

def test_reflected_handshake_message_is_rejected(handshake_setup):
    hs = handshake_setup

    # A gateway signature must not be accepted as a node signature.
    with pytest.raises(ValueError, match="Invalid RSA-PSS signature"):
        verify(
            hs["gateway_private"].public_key(),
            NODE_ROLE,
            hs["transcript_hash"],
            hs["gateway_signature"],
        )