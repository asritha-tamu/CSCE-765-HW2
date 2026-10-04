import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_parameters,
    load_pem_private_key,
)

# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------

PROTOCOL = b"CSCE465-HS-v2"
GROUP = b"ffdhe3072"

GATEWAY_ID = b"gateway"
NODE_ID = b"node"

GATEWAY_ROLE = b"gateway"
NODE_ROLE = b"node"

DH_BYTES = 384
NONCE_BYTES = 16


# ------------------------------------------------------------
# Hash and HMAC
# ------------------------------------------------------------

def sha256(data):
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def hmac_sha256(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


# ------------------------------------------------------------
# Transcript encoding
# ------------------------------------------------------------

def field(data):
    """4-byte big-endian length followed by the data."""
    return len(data).to_bytes(4, "big") + data


def make_transcript(gateway_pub, node_pub,
                    gateway_nonce, node_nonce):

    fields = [
        PROTOCOL,
        GROUP,
        GATEWAY_ID,
        NODE_ID,
        gateway_pub,
        node_pub,
        gateway_nonce,
        node_nonce,
    ]

    return b"".join(field(x) for x in fields)


def check_transcript(transcript):
    """Reject malformed transcript before hashing."""

    fields = []
    pos = 0

    for _ in range(8):

        if pos + 4 > len(transcript):
            raise ValueError("Malformed transcript")

        length = int.from_bytes(
            transcript[pos:pos + 4], "big"
        )

        pos += 4

        if pos + length > len(transcript):
            raise ValueError("Incorrect field length")

        fields.append(transcript[pos:pos + length])
        pos += length

    if pos != len(transcript):
        raise ValueError("Trailing data in transcript")

    if fields[0] != PROTOCOL:
        raise ValueError("Wrong protocol")

    if fields[1] != GROUP:
        raise ValueError("Wrong DH group")

    if fields[2] != GATEWAY_ID:
        raise ValueError("Unexpected gateway identity")

    if fields[3] != NODE_ID:
        raise ValueError("Unexpected node identity")

    if len(fields[4]) != DH_BYTES:
        raise ValueError("Invalid gateway public value")

    if len(fields[5]) != DH_BYTES:
        raise ValueError("Invalid node public value")

    if len(fields[6]) != NONCE_BYTES:
        raise ValueError("Invalid gateway nonce")

    if len(fields[7]) != NONCE_BYTES:
        raise ValueError("Invalid node nonce")

    return fields


# ------------------------------------------------------------
# RSA-PSS
# ------------------------------------------------------------

def sign(private_key, role, TH):

    return private_key.sign(
        role + TH,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify(public_key, role, TH, signature):

    try:
        public_key.verify(
            signature,
            role + TH,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception:
        raise ValueError("Invalid RSA-PSS signature")


# ------------------------------------------------------------
# Key derivation
# ------------------------------------------------------------

def derive_keys(Z, TH):

    K_master = sha256(
        b"CSCE465-KDF-v1" + Z + TH
    )

    K_g2n_enc = hmac_sha256(
        K_master,
        b"gateway-to-node encryption" + TH
    )

    K_g2n_mac = hmac_sha256(
        K_master,
        b"gateway-to-node MAC" + TH
    )

    K_n2g_enc = hmac_sha256(
        K_master,
        b"node-to-gateway encryption" + TH
    )

    K_n2g_mac = hmac_sha256(
        K_master,
        b"node-to-gateway MAC" + TH
    )

    session_id = hmac_sha256(
        K_master,
        b"session identifier" + TH
    )[:8]

    return (
        K_master,
        K_g2n_enc,
        K_g2n_mac,
        K_n2g_enc,
        K_n2g_mac,
        session_id,
    )


# ------------------------------------------------------------
# Main handshake
# ------------------------------------------------------------

def main():

    print("Loading DH parameters...")

    with open("ffdhe3072.pem", "rb") as f:
        parameters = load_pem_parameters(f.read())

    print("Loading RSA keys...")

    with open("gateway_key.pem", "rb") as f:
        gateway_private = load_pem_private_key(
            f.read(), password=None
        )

    with open("node_key.pem", "rb") as f:
        node_private = load_pem_private_key(
            f.read(), password=None
        )

    # Check RSA key sizes
    assert gateway_private.key_size == 3072
    assert node_private.key_size == 3072

    # --------------------------------------------------------
    # Fresh ephemeral DH values
    # --------------------------------------------------------

    gateway_dh = parameters.generate_private_key()
    node_dh = parameters.generate_private_key()

    gateway_pub = gateway_dh.public_key()
    node_pub = node_dh.public_key()

    gateway_pub_bytes = gateway_pub.public_numbers().y.to_bytes(
        DH_BYTES, "big"
    )

    node_pub_bytes = node_pub.public_numbers().y.to_bytes(
        DH_BYTES, "big"
    )

    # --------------------------------------------------------
    # Fresh nonces
    # --------------------------------------------------------

    gateway_nonce = os.urandom(NONCE_BYTES)
    node_nonce = os.urandom(NONCE_BYTES)

    # --------------------------------------------------------
    # Canonical transcript
    # --------------------------------------------------------

    transcript = make_transcript(
        gateway_pub_bytes,
        node_pub_bytes,
        gateway_nonce,
        node_nonce,
    )

    # MUST validate before hashing
    check_transcript(transcript)

    TH = sha256(transcript)

    print("\nTranscript hash:")
    print(TH.hex())

    # --------------------------------------------------------
    # Sign role || TH
    # --------------------------------------------------------

    gateway_signature = sign(
        gateway_private,
        GATEWAY_ROLE,
        TH,
    )

    node_signature = sign(
        node_private,
        NODE_ROLE,
        TH,
    )

    # --------------------------------------------------------
    # Verify signatures
    # --------------------------------------------------------

    verify(
        node_private.public_key(),
        NODE_ROLE,
        TH,
        node_signature,
    )

    verify(
        gateway_private.public_key(),
        GATEWAY_ROLE,
        TH,
        gateway_signature,
    )

    print("Gateway signature: VERIFIED")
    print("Node signature:    VERIFIED")

    # --------------------------------------------------------
    # Diffie-Hellman
    # --------------------------------------------------------

    Z_gateway = gateway_dh.exchange(node_pub)
    Z_node = node_dh.exchange(gateway_pub)

    assert Z_gateway == Z_node

    # Ensure exactly 384 bytes
    Z = int.from_bytes(Z_gateway, "big").to_bytes(
        DH_BYTES, "big"
    )

    print("DH shared secret:  MATCHED")

    # --------------------------------------------------------
    # Derive keys
    # --------------------------------------------------------

    gateway_keys = derive_keys(Z, TH)
    node_keys = derive_keys(Z, TH)

    assert gateway_keys == node_keys

    (
        K_master,
        K_g2n_enc,
        K_g2n_mac,
        K_n2g_enc,
        K_n2g_mac,
        session_id,
    ) = gateway_keys

    print("\nDerived values:")
    print("K_master   =", K_master.hex())
    print("K_g2n_enc  =", K_g2n_enc.hex())
    print("K_g2n_mac  =", K_g2n_mac.hex())
    print("K_n2g_enc  =", K_n2g_enc.hex())
    print("K_n2g_mac  =", K_n2g_mac.hex())
    print("session_id  =", session_id.hex())

    print("\nHandshake successful!")

if __name__ == "__main__":
    main()