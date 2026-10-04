from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


COMMAND = b'{"action":"READ","path":"notes.txt"}'


def encrypt(key, nonce, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt(key, nonce, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def relay_modify(ciphertext, position,original, modified):
    """
    Modify the ciphertext without knowing the AES key.

    CTR encryption has the form:
        C = P XOR keystream

    Therefore:
        C' = C XOR P XOR P'
    """
    modified_ciphertext = bytearray(ciphertext)

    for i in range(len(original)):
        modified_ciphertext[position + i] ^= original[i] ^ modified[i]

    return bytes(modified_ciphertext)


def main():
    key = os.urandom(32)
    nonce = os.urandom(16)

    print("Original command:")
    print(COMMAND.decode())

    # Encrypt the command.
    ciphertext = encrypt(key, nonce, COMMAND)

    print("\nCiphertext:")
    print(ciphertext.hex())

    # Change READ -> WRIT.
    original_word = b"READ"
    modified_word = b"WRIT"

    print("\nRelay modification:")
    print("Original:", original_word)
    print("Modified:", modified_word)

    # Show the XOR relation.
    xor_mask = bytes(a ^ b for a, b in zip(original_word, modified_word))

    print("\nXOR mask (READ XOR WRIT):")
    print(xor_mask.hex())

    position = COMMAND.index(original_word)    
    modified_ciphertext = relay_modify(
        ciphertext,
        position,
        original_word,
        modified_word
    )

    print("\nModified ciphertext:")
    print(modified_ciphertext.hex())

    # Receiver decrypts the modified ciphertext.
    received = decrypt(key, nonce, modified_ciphertext)

    print("\nReceiver processes modified command:")
    print(received.decode())

    # Replay the original ciphertext.
    replayed = decrypt(key, nonce, ciphertext)

    print("\nReplay of original ciphertext:")
    print(replayed.decode())

    print("\nReceiver processes replay:")
    print(replayed.decode())


if __name__ == "__main__":
    main()