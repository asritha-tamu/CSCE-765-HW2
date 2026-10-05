# AI-USAGE

### Entry 1
**Tool/model and date:** ChatGPT (GPT-5.6 Luna), October 2026  
**Purpose:** Understand the AES-CTR experiment.   
**What I used:** Asked how AES-CTR works and why changing ciphertext can change the decrypted message.  
**What I changed:** Used the explanation to describe the ciphertext modification in my report.  
**How I tested it:** Ran the program with the original and modified ciphertext and compared the receiver's output.  
**One error, limitation, or rejected suggestion:** The explanation did not replace testing; I verified the behavior by running my program.

### Entry 2
**Tool/model and date:** ChatGPT (GPT-5.6 Luna), October 2026  
**Purpose:** Understand the secure record format and its checks.   
**What I used:** Asked what the `open_record()` function checks before returning the decrypted message.  
**What I changed:** Reviewed the function and made sure the report explained the sequence number and MAC checks.  
**How I tested it:** Tested a valid record and records with modified ciphertext or headers.  
**One error, limitation, or rejected suggestion:** An invalid MAC raises an error, so the test needed to check for the expected failure instead of expecting normal output.

### Entry 3
**Tool/model and date:** ChatGPT (GPT-5.6 Luna), October 2026  
**Purpose:** Understand handshake security and testing.   
**What I used:** Asked why the handshake uses nonces and digital signatures, and how to test an invalid signature.  
**What I changed:** Used the explanation to review the rejection tests and describe their purpose.  
**How I tested it:** Ran the tests and checked that invalid signatures and reflected messages were rejected.  
**One error, limitation, or rejected suggestion:** Some tests check individual security properties and do not replace testing the complete handshake flow.
