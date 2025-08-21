# Jenan | 1210345 | Phase 3 | Server
import socket
import hashlib
import secrets
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Bob's RSA Key Setup (321-digit primes) 
bob_p = 542309975809760595286562106973834448331913712111854232607032538281889929034387258038186252673306188432437904245417849851856907004426028292986951823050924636627753949240293375184002876800111434697656049334860520406953087181894211543094433055040053339672065507651500478429848180873887574173366239074642673070940259435327269
bob_q = 484142697764245480817650754226670250466938491720005928422360014036677703796908614063874571550831163423052660362168110626391616634912064082334290659147215960823344439722736238539727989992721876141823825047396983332016633815261681666312820593493146967485207414661091745520108116407588174923000532634704271130108364248276491

def mod_pow(base, exponent, modulus):
    
    return pow(base, exponent, modulus)

# modular inverse function:
def modinv(a, m):

    return pow(a, -1, m)

# N= p*q:
bob_N = bob_p * bob_q
print("Bob's Public Key N:", bob_N)

bob_phi = (bob_p - 1) * (bob_q - 1)
bob_e = 65537 # i've used the general component of RSA_e

#Check that they are relatively prime numbers-> GCD= 1:

while math.gcd(bob_e, bob_phi) != 1:
    bob_e += 2
bob_d = modinv(bob_e, bob_phi)

# RFC 3526 MODP -- 2048 bit (as required in our project)
g = 2 #generator 

m = int("""FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF""".replace("\n", "").replace(" ", ""), 16)

alice_N = 84405880333938884158292603053052188359085998451887618791986325682438672921464471053838356621769251332418580574340000615293038298977128351178899797542946584941530634721760962859220264142627343441948122192163704567081497370073957552076053910640799105735388957851075815169077972151821417647643867831609335040279840851190184963102056380882281478566960581516842986601353153630471453003828508671670211271317281720323445137386687018919798111446557846040809390028769259091997854025220163241911156423076324199153781455459492489714525297926520471248775734234352950079763990404873949105109180479310560089131187386533703202030753350865855982482854044389
alice_e = 65537 #general for RSA 

#Hash process
def sha256_int(*args):
    m = hashlib.sha256()
    for x in args:
        m.update(str(x).encode() if isinstance(x, int) else x)
    return int(m.hexdigest(), 16)

#signing using RSA
def rsa_sign(message_int, d, N):
    return mod_pow(message_int % N, d, N)

#verify the signature
def rsa_verify(signature_int, e, N):
    return mod_pow(signature_int, e, N)

def send_big(sock, value):
    data = str(value).encode()
    sock.sendall(len(data).to_bytes(8, 'big') + data)

def recv_big(sock):
    size_data = sock.recv(8)
    if not size_data:
        raise EOFError("Connection closed while reading size")
    size = int.from_bytes(size_data, 'big')
    buf = b''
    while len(buf) < size:
        #trim to chunks
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise EOFError("Connection closed while reading data")
        buf += chunk
    return int(buf.decode())

def send_bytes(sock, value):
    sock.sendall(len(value).to_bytes(4, 'big') + value)

def recv_bytes(sock):
    size = int.from_bytes(sock.recv(4), 'big')
    return sock.recv(size)

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
    ciphertext = encrypt_message(key, text)
    length = len(ciphertext)
    sock.sendall(length.to_bytes(4, 'big') + ciphertext)
    print(f"[Encrypted] IV={ciphertext[:16].hex()} | Length={length-16} | Sent='{text}'")

def recv_enc_msg(sock: socket.socket, key: bytes, tag: str="") -> str:
    hdr = sock.recv(4)
    if len(hdr) < 4:
        raise EOFError("Connection closed")
    total = int.from_bytes(hdr, 'big')
    ciphertext = b''
    while len(ciphertext) < total:
        chunk = sock.recv(total - len(ciphertext))
        if not chunk:
            raise EOFError("Connection closed while reading encrypted data")
        ciphertext += chunk
    decrypted = decrypt_message(key, ciphertext)
    print(f"[Decrypted] IV={ciphertext[:16].hex()} | Length={total-16} | Received='{decrypted}'")
    return decrypted

# Server Logic
#create a connection (TCP)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #listen to all interfaces ips
    s.bind(('0.0.0.0', 5000))
    s.listen(1)
    print("Server started, Waiting for Client ...")

    conn, addr = s.accept()
    with conn:
        print(f"Connected by: {addr}")
        for round_id in range(2):  # repeat for 2 game rounds
            print(f"\n===== ROUND {round_id+1} START =====")
        
        #RGN: RA,RB   
        A = recv_big(conn)
        RA = recv_bytes(conn)
        print(f"Alice sent: A = {A}, RA={RA.hex()}")

        b = secrets.randbits(2048)
       
        RB = secrets.token_bytes(32)
        B = mod_pow(g, b, m)
        bob_K = mod_pow(A, b, m)
        
        print(f"Bob's private key (b) = {b} , Session key={bob_K}")

        bob_ip = b"192.168.1.104" #my server ip
        
        alice_ip = b"192.168.1.108" #my client ip
        H_bob = sha256_int(B, A, RB, RA, bob_ip, alice_ip, bob_K)
        print("[Bob] H_bob =", H_bob)

        SB = rsa_sign(H_bob, bob_d, bob_N)
        
        ## SB+= 1 for test case 2 to lead an authentication failure ##
        
        # these lines for debugging:
        print("[Server:Bob] SB =", SB)
        print("[Server:Bob] RSA verification(SB, bob_e, bob_N) =", rsa_verify(SB, bob_e, bob_N))
        print("[Server:Bob] H%N =", H_bob % bob_N)

        send_big(conn, B)
        send_bytes(conn, RB)
        send_big(conn, SB)

        print("Waiting for Alice's SA...")
        
        SA = recv_big(conn)
        H_alice = sha256_int(A, B, RA, RB, alice_ip, bob_ip, bob_K)
        
        #check if the original computed hash is similar 
        if rsa_verify(SA, alice_e, alice_N) == H_alice % alice_N:
            
            print("Alice authenticated successfully.")
        else:
            print("Alice authentication failed!")
            exit(1)

        session_key = hashlib.sha256(str(bob_K).encode()).digest()
        print("--Secure AES session key established--")

        # Game core logic
        send_enc_msg(conn, session_key, "|| Welcome to Guessing Game || \n1. Start the Game\n 2. Exit\nPlease Enter a choice:")
        secret = secrets.randbelow(100) + 1
        while True:
            choice = recv_enc_msg(conn, session_key).strip()
            #check if the choice is valid
            if choice == '2':
                send_enc_msg(conn, session_key, "Good Bye!")
                break
            if choice != '1':
                send_enc_msg(conn, session_key, "Invalid option!")
                continue
            #generate a secret num to be guessed
            secret = secrets.randbelow(100) + 1
            attempts = 0
            while True:
                send_enc_msg(conn, session_key, "Guess a number between 1 till 100:")
                guess_str = recv_enc_msg(conn, session_key).strip()
                attempts += 1
                try:
                        num = int(guess_str)
                        
                        if num < 1 or num > 100:
                            
                            response = "Oops! Your number is outside the valid range (1-100). Try again."
                            
                        elif num == secret:
                            
                            response = f"Correct! You guessed it in {attempts} tries."
                            send_enc_msg(conn, session_key, response)
                            break
                        
                        elif num < secret:
                            response = "Too low! Try a higher number."
                        else:
                            response = "Too high! Try a lower number."
                
                except ValueError:
                        response = "Invalid input. Please enter a number between 1 and 100."

                send_enc_msg(conn, session_key, response)

            del b
            del bob_K
            print(f"[ROUND {round_id+1}] Key materials cleared.")

        print("[SERVER] Session ended. Closing connection...")