README || Phase 3: RSA| Diffie Hellman| AES Encrypted Guessing Game

Student Name & ID: Jenan Mohammad-1210345

----------------------------------------------------------------
|| Overview ||

> This project implements a secure client-server guessing game using:

  - RSA (321-digit primes) for digital signatures and authentication
  - Diffie-Hellman (RFC3526 MODP 2048-bit) for key exchange
  - AES-256 in CBC mode for encryption
> Mutual authentication is done using RSA signatures over a SHA-256 hash of exchanged values (A, B, RA, RB, IPs, Shared Key).
> Two full authentication rounds are executed to comply with test case requirements.
> After authentication, encrypted communication begins:
  - The menu, user choices, and guesses are encrypted using the session key derived from Diffie-Hellman.
  - Each message uses a fresh IV and PKCS#7 padding.

1.What have been Used:
- Python
- PyCryptodome (for AES)
- socket module (for TCP communication)
- hashlib (for SHA-256)
- secrets (for secure random values)
- math (for GCD and other calculations)

2. Features:
- RSA-based digital signature authentication
- Diffie-Hellman key exchange (2048-bit MODP Group)
- AES-256 CBC encryption
- SHA-256 used for digest and session key generation
- Session variables deleted after each round.

3. File Structure:
- server.py → Main server(BOB)
- client.py → Main client(Alice)
- computation.py -> to compute N correctly and took them in server&client code files.
-Video
4. How to Run:

A. Local Testing:
------------------
Step 1: Start the server ( on VM)
python3 Server.py

Step 2: Start the client ( on my local machine: windows)
python Client.py

- Change "s.connect()" IP in client code to match the server IP.

5. Test Cases Implemented:
--------------------------
Test Case 1: Normal Run (Authentication success)
- Both client and server authenticate successfully.
- Two full rounds of guessing game are executed.
- Session keys and secrets deleted after rounds.

Test Case 2: Trudy pretending to be Bob
- Server uses fake RSA keys {SB}
- Signature verification fails at Alice’s side.
- Authentication is rejected.

Test Case 3: Trudy pretending to be Alice
- Client uses fake RSA keys {SA}
- Server detects signature mismatch.
- Authentication is rejected.

6. Security Summary:
-----------------------------
A. Key Exchange:
- Alice generates private key "a", computes A = g^a mod m.
- Bob generates private key "b", computes B = g^b mod m.
- Shared key K = B^a mod m = A^b mod m.

B. Mutual Authentication:
- Exchange of random numbers (RA, RB) and IPs.
- H = SHA256(A, B, RA, RB, IPs, K)
- Each side signs their H using their private RSA key.
- The other side verifies the signature.

C. Encryption:
- Session key derived from SHA256(K)
- AES-256 CBC mode used for game messages
- Random IV used for each encryption and it has been printed.

-----------------------
- Keys 'a', 'K', and session variables are deleted after each round.
- Ensures new values in every round for security.
- Printing statements to demonstrate values (A, B, K, signatures) for debugging and validation.
- IPs are hardcoded but can be dynamically detected if needed.
- All values transmitted over socket are properly encoded and chunked.

7. Troubleshooting:
--------------------
- "Connection closed" -> Check IP and server status.
- "RSA verification failed" -> Check for key mismatch.
- Use exact RSA keys and ensure consistent message format.


