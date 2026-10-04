from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Record constants
VERSION = 1
GATEWAY_TO_NODE = 0
NODE_TO_GATEWAY = 1

HEADER_SIZE = 15   # 1 + 1 + 8 + 1 + 4
IV_SIZE = 16       # 8-byte session ID + 8-byte sequence
TAG_SIZE = 32      # HMAC-SHA-256 output


def make_header(version, direction, sequence, message_type, ciphertext_length):
    """Create the record header using the required field sizes."""
    if not 0 <= version <= 255:
        raise ValueError("Invalid version")
    if direction not in (GATEWAY_TO_NODE, NODE_TO_GATEWAY):
        raise ValueError("Invalid direction")
    if not 0 <= sequence < 2**64:
        raise ValueError("Invalid sequence number")
    if not 0 <= message_type <= 255:
        raise ValueError("Invalid message type")
    if not 0 <= ciphertext_length < 2**32:
        raise ValueError("Invalid ciphertext length")

    return (
        version.to_bytes(1, "big")
        + direction.to_bytes(1, "big")
        + sequence.to_bytes(8, "big")
        + message_type.to_bytes(1, "big")
        + ciphertext_length.to_bytes(4, "big")
    )


def encrypt_ctr(key, iv, plaintext):
    """Encrypt using AES-256-CTR."""
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    if len(iv) != IV_SIZE:
        raise ValueError("IV must be 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_ctr(key, iv, ciphertext):
    """Decrypt using AES-256-CTR."""
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    if len(iv) != IV_SIZE:
        raise ValueError("IV must be 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def calculate_mac(key, data):
    """Calculate HMAC-SHA-256."""
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def verify_mac(key, data, tag):
    """Verify HMAC using the library's constant-time verification."""
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    h.verify(tag)


def seal(K_enc, K_mac, session_id, sequence, direction,
         message_type, plaintext):
    """
    Encrypt and authenticate a message.

    Returns:
        header || IV || ciphertext || tag
    """
    if len(session_id) != 8:
        raise ValueError("session_id must be 8 bytes")
    if not 0 <= sequence < 2**64:
        raise ValueError("Invalid sequence number")
    if direction not in (GATEWAY_TO_NODE, NODE_TO_GATEWAY):
        raise ValueError("Invalid direction")
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    # IV = session_id (8 bytes) || sequence (8 bytes)
    iv = session_id + sequence.to_bytes(8, "big")

    # Encrypt the plaintext
    ciphertext = encrypt_ctr(K_enc, iv, plaintext)

    # Build the header
    header = make_header(
        VERSION, direction, sequence, message_type, len(ciphertext)
    )

    # Authenticate the header, IV, and ciphertext
    tag = calculate_mac(K_mac, header + iv + ciphertext)

    return header + iv + ciphertext + tag


def open_record(K_enc, K_mac, session_id, expected_sequence,
                expected_direction, record):
    """
    Verify and decrypt a record.

    Returns plaintext only after all checks succeed.
    """
    if len(session_id) != 8:
        raise ValueError("session_id must be 8 bytes")
    if not 0 <= expected_sequence < 2**64:
        raise ValueError("Invalid expected sequence number")
    if expected_direction not in (GATEWAY_TO_NODE, NODE_TO_GATEWAY):
        raise ValueError("Invalid expected direction")
    if not isinstance(record, bytes):
        raise TypeError("record must be bytes")

    # A record must contain at least header, IV, and tag
    if len(record) < HEADER_SIZE + IV_SIZE + TAG_SIZE:
        raise ValueError("Record is too short")

    # Extract header fields
    header = record[:HEADER_SIZE]
    version = header[0]
    direction = header[1]
    sequence = int.from_bytes(header[2:10], "big")
    message_type = header[10]
    ciphertext_length = int.from_bytes(header[11:15], "big")

    # Validate header fields
    if version != VERSION:
        raise ValueError("Unsupported version")
    if direction != expected_direction:
        raise ValueError("Wrong message direction")
    if sequence != expected_sequence:
        raise ValueError("Unexpected sequence number")

    # Extract IV, ciphertext, and tag
    iv_start = HEADER_SIZE
    ciphertext_start = iv_start + IV_SIZE
    ciphertext_end = ciphertext_start + ciphertext_length
    tag_start = ciphertext_end

    if len(record) != tag_start + TAG_SIZE:
        raise ValueError("Invalid record length")

    iv = record[iv_start:ciphertext_start]
    ciphertext = record[ciphertext_start:ciphertext_end]
    tag = record[tag_start:]

    # Check that the IV matches the session ID and sequence
    expected_iv = session_id + sequence.to_bytes(8, "big")
    if iv != expected_iv:
        raise ValueError("Invalid IV")

    # IMPORTANT: Verify the MAC before decrypting.
    # InvalidSignature is raised if the tag does not match.
    verify_mac(K_mac, header + iv + ciphertext, tag)

    # Decrypt only after successful verification
    plaintext = decrypt_ctr(K_enc, iv, ciphertext)

    return plaintext