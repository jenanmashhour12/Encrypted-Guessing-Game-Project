#Jenan | 1210345 | Phase 3
import socket
import hashlib
import secrets
import math  # to use math.gcd for simplification
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Alice's RSA Key (321-digit primes)
alice_p = 549914234622513557467810323099394370724987742425389616106010469076340649152978812071396462422299510731999830695739817556341761993920703139439501214210047458839399755721703710879178451879971307982148393714351095412175271272938723740705514939497052648237105448412162681862641380133062293918906416156681954569108423345993717
alice_q = 153489171619423464315524578738566583432313140317814148217967033282065052310320450834008227824755206100771588016792072560059345436492964590089215007269087066851684696675833654125549616689371184291353716325125461351968290136241666230472310028229322960995475350373773220886115352603087802306982422276575523781023346652813617

# Compute RSA parameters using p*q -> N
alice_N = alice_p * alice_q
print("Alice's Public Key N:", alice_N)

alice_phi = (alice_p - 1) * (alice_q - 1)
alice_e_component = 65537

# Ensure e is coprime with O(N)
while math.gcd(alice_e_component, alice_phi) != 1:
    alice_e_component += 2

# Modular inverse of e mod O(N)
alice_d = pow(alice_e_component, -1, alice_phi)

#RFC3526 MODP Group -- 2048-bit
g = 2  # generator
m = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF
""".replace("\n", "").replace(" ", ""), 16)

# Bob's Public Key 
bob_N = 262555414713000201741300701903677162584013452717134030514772313443063920396753744377645854099839531892736361620591307187439302371822845014545971590210071667745196015236723488527943231024306761889301587519086819843168067397979413630939249850714916493853448930658277535942624263720742466817013146829267442706673204109993206471469077924091683472977896343575042921213495925233634995191071003395527892325092658270314490965899122961541474345326944232034064143755646802020731629615435574571230209972369252658944773144300781100091132047982498480113600917906835368263672974285855725853794261877927477336696443224591103723636962845135457410611783933079
bob_e = 65537

def sha256_int(*args):
    m = hashlib.sha256()
    for x in args:
        m.update(str(x).encode() if isinstance(x, int) else x)
    return int(m.hexdigest(), 16)

def rsa_sign(message_int, d, N):
    return pow(message_int % N, d, N)

def rsa_verify(signature_int, e, N):
    return pow(signature_int, e, N)

def send_big(sock, val):
    val_bytes = str(val).encode()
    sock.sendall(len(val_bytes).to_bytes(8, 'big') + val_bytes)

def recv_big(sock):
    size = int.from_bytes(sock.recv(8), 'big')
    data = b''
    while len(data) < size:
        data += sock.recv(size - len(data))
    return int(data.decode())

def send_bytes(sock, value):
    sock.sendall(len(value).to_bytes(4, 'big') + value)

def recv_bytes(sock):
    size = int.from_bytes(sock.recv(4), 'big')
    buf = b''
    while len(buf) < size:
        buf += sock.recv(size - len(buf))
    return buf

#AES- CBC mode :
def encrypt_message(key: bytes, plaintext: str) -> bytes:
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext.encode(), AES.block_size))

def decrypt_message(key: bytes, data: bytes) -> str:
 #decryption the message while taking the first 16 bit for IV , the rest for the message:
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

def send_enc_msg(sock: socket.socket, key: bytes, text: str, tag: str=""):
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    payload = iv + cipher.encrypt(pad(text.encode(), AES.block_size))
    sock.sendall(len(payload).to_bytes(4, 'big') + payload)
    print(f"[Alice Sent {tag}] IV={iv.hex()}  '{text}'")
    
    
def recv_enc_msg(sock, key) -> str:
    size = int.from_bytes(sock.recv(4), 'big')
    data = b''
    while len(data) < size:
        data += sock.recv(size - len(data))
    msg = decrypt_message(key, data)
    print(f"[Decrypted] IV={data[:16].hex()} | Received='{msg}'\n")
    return msg

# main logic 
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('127.0.0.1', 5000)) #ip for local host
    print("Connected to server..")

    for round in range(2):  # repeat full authentication twice for test case 1
        print(f"===== ROUND {round+1} START =====")
        a = secrets.randbits(2048)
        RA = secrets.token_bytes(32)
        A = pow(g, a, m)
        print(f"Alice: a={a}, RA={RA.hex()}, A={A}")

        send_big(s, A)
        send_bytes(s, RA)

        B = recv_big(s)
        RB = recv_bytes(s)
        SB = recv_big(s)
        print(f"Received from Bob: B={B}, RB={RB.hex()}, SB={SB}")

        alice_K = pow(B, a, m)
        print(f"Alice's Shared Key: {alice_K}")

        bob_ip = b"192.168.1.104"
        alice_ip = b"192.168.1.108"
        H_bob = sha256_int(B, A, RB, RA, bob_ip, alice_ip, alice_K)

        print("[Alice] H_bob =", H_bob)
        print("[Alice:RSA VER] SB=", rsa_verify(SB, bob_e, bob_N))
        
        if rsa_verify(SB, bob_e, bob_N) != H_bob % bob_N:
            
            print("[Authentication FAIL] Bob authentication failed! Exiting...")
            
            exit(1)
        print("[Authentication PASS] Bob authenticated to Alice successfully.")

        H_alice = sha256_int(A, B, RA, RB, alice_ip, bob_ip, alice_K)
        SA = rsa_sign(H_alice, alice_d, alice_N)
        
        #this will enable for test case 3 only !
        # SA += 10
        send_big(s, SA)

        session_key = hashlib.sha256(str(alice_K).encode()).digest()
        print("[Alice:Client] AES session key established. Entering game.\n")

        while True:
            menu = recv_enc_msg(s, session_key)
            print(menu, end='')
            choice = input().strip()
            send_enc_msg(s, session_key, choice)

            if choice == '2':
                bye = recv_enc_msg(s, session_key)
                print(bye)
                break
            if choice != '1':
                continue

            send_enc_msg(s, session_key, "Ready to guess")
            while True:
                response = recv_enc_msg(s, session_key)
                print(response)
                if "Correct" in response or "Invalid" in response:
                    break
                guess = input("Please enter your guess (1-100): ").strip()
                send_enc_msg(s, session_key, guess)
                
    # delete key values for test compliance
        del a
        del alice_K

    print("[Client] Secure sessions complete. Disconnecting,BYE...")

