import os
import socket
import json
import secrets
import hashlib
import time
import threading
from dotenv import load_dotenv, set_key
from fastecdsa import curve
from fastecdsa.point import Point
from utils.ecops.koblitz import encode_reals, decode_reals
from utils.schnorr.signature import schnorr_signature_component
from utils.pedersen.committment import vector_commit, derive_Gi, hash_to_scalar
from decimal import Decimal

load_dotenv()

poc_dt_id = os.getenv("DT_ID")
KEYS_PORT = int(os.getenv("KEYS_PORT", 8080))
DATA_PORT = int(os.getenv("DATA_PORT", 8081))
TA_IP = os.getenv("TA_IP")
EDGE_IP = os.getenv("EDGE_IP")
EDGE_PORT = int(os.getenv("EDGE_PORT", 8082))

PRECISION = 10**6

class KeyManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.curve = curve.secp256k1
        self.q = self.curve.q          # Curve order
        self.P = self.curve.G          # Generator point


    def recv_key_pair(self):
        """
        Receives the public-private key pair from trusted authority.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("0.0.0.0", KEYS_PORT))
            server.listen(1)
            print(f"[{poc_dt_id}] Waiting for key pair from Trusted Authority...")
            conn, addr = server.accept()
            if addr[0] != TA_IP:
                print(f"[{poc_dt_id}] Connection from unauthorized IP {addr[0]}. Closing connection.")
                conn.close()
                return
            with conn:
                print(f"[{poc_dt_id}] Connected by", addr)
                buffer = ""
                while True:
                    chunk = conn.recv(4096).decode("utf-8")
                    if not chunk:
                        break
                    buffer += chunk
                    if "\n" in buffer:
                        break
                key_pair = json.loads(buffer.strip())
                set_key(".env", f"{poc_dt_id}_sk", str(key_pair["sk_org"]))
                set_key(".env", f"{poc_dt_id}_pk_x", str(key_pair["pk_org"]["x"]))
                set_key(".env", f"{poc_dt_id}_pk_y", str(key_pair["pk_org"]["y"]))
                self.private_key = key_pair["sk_org"]
                self.public_key = Point(key_pair["pk_org"]["x"], key_pair["pk_org"]["y"], curve.secp256k1)
                print(f"[{poc_dt_id}] Key pair received and stored in .env")
    
    def get_keys(self):
        """
        Retrieves the stored keys from the .env file or receives them from the trusted authority.
        """
        priv_key_str = os.getenv(f"{poc_dt_id}_sk")
        if not priv_key_str:
            self.recv_key_pair()
            return
        self.private_key = int(priv_key_str)
        pk_x = int(os.getenv(f"{poc_dt_id}_pk_x"))
        pk_y = int(os.getenv(f"{poc_dt_id}_pk_y"))
        self.public_key = Point(pk_x, pk_y, curve.secp256k1)


class CryptoManager:
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager

    def encrypt_data(self, data):
        """
        Encrypts the data to be relayed to the destination digital twin.
        """
        q = self.key_manager.q
        P = self.key_manager.P
        pk_org = self.key_manager.public_key

        r = secrets.randbelow(q - 1) + 1
        M = encode_reals(data)
        c_t = r * pk_org
        c_m = r * P + M

        hM = hashlib.sha256(
            M.x.to_bytes(32, "big") + M.y.to_bytes(32, "big")
        ).digest()

        return c_t, c_m, hM

class CommunicationManager:
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager

    def send_data_to_edge(self, data: bytes, dest_dt_id, EDGE_PORT = 8084):
        """
        Communicates with the edge server to relay encrypted data.
        """
        
        q = self.key_manager.q
        secrect_key = self.key_manager.private_key
        scaled_data = [int(Decimal(str(v))) * PRECISION for v in data]

        k_values = []
        for _ in scaled_data:
            k_values.append(secrets.randbelow(q - 1) + 1)
        kr = secrets.randbelow(q - 1) + 1

        Q = [derive_Gi(i) for i in range(1, len(scaled_data) + 1)]
        P = self.key_manager.P
        C = vector_commit(scaled_data, secrect_key, Q, P)
        R = None
        for ki, Q_i in zip(k_values, Q):
            if R is None:
                R = ki * Q_i
            else:
                R = R + ki * Q_i
        R = R + kr * P
        
        e = hash_to_scalar(b"".join(
            Q_i.x.to_bytes(32, "big") + Q_i.y.to_bytes(32, "big") for Q_i in Q
        ) + R.x.to_bytes(32, "big") + R.y.to_bytes(32, "big") + C.x.to_bytes(32, "big") + C.y.to_bytes(32, "big") + P.x.to_bytes(32, "big") + P.y.to_bytes(32, "big"))

        v = []
        for ki, value in zip(k_values, scaled_data):
            s = schnorr_signature_component(ki, e, value, q)
            v.append(s)
        
        u = schnorr_signature_component(kr, e, secrect_key, q)
        
        cm = CryptoManager(self.key_manager)
        c_t, c_m, hM = cm.encrypt_data(data)

        payload = {
            "src_dt_id": poc_dt_id,
            "dest_dt_id": dest_dt_id,
            "curve": "secp256k1",
            "u": u,
            "R": {
                "x": R.x,
                "y": R.y
            },
            "C": {
                "x": C.x,
                "y": C.y
            },
            "v": v,
            "c_t": {
                "x": c_t.x,
                "y": c_t.y
            },
            "c_m": {
                "x": c_m.x,
                "y": c_m.y
            },
            "hM": hM.hex(),
            "Torg": time.time()
        }
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((EDGE_IP, EDGE_PORT))
        except ConnectionRefusedError:
            print(f"[{poc_dt_id}] Edge server not available")
            return
        s.sendall((json.dumps(payload) + "\n").encode())
        s.close()
        return
    
    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("0.0.0.0", DATA_PORT))
            server.listen(5)
            print(f"[{poc_dt_id}] Listening for re-encrypted data...")

            while True:
                conn, addr = server.accept()
                if addr[0] != EDGE_IP:
                    print(f"[{poc_dt_id}] Connection from unauthorized IP {addr[0]}. Closing connection.")
                    conn.close()
                    continue
                with conn:
                    self.handle_connection(conn, addr)

    def handle_connection(self, conn, addr):
        print(f"[{poc_dt_id}] Connection from", addr)
        buffer = ""

        while True:
            chunk = conn.recv(4096).decode("utf-8")
            if not chunk:
                break
            buffer += chunk
            if "\n" in buffer:
                break

        payload = json.loads(buffer.strip())
        self.decrypt_and_verify(payload)

    def decrypt_and_verify(self, data):
        Tproxy = data["Tproxy"]
        if abs(time.time() - Tproxy) > 10:
            print(f"[{poc_dt_id}] Dropping message: stale timestamp")
            return

        CURVE = curve.secp256k1
        R = Point(
            data["R"]["x"],
            data["R"]["y"],
            CURVE
        )
        C = Point(
            data["C"]["x"],
            data["C"]["y"],
            CURVE
        )
        u = data["u"]
        v = data["v"]
        CT_prime = Point(
            data["c_t_prime"]["x"],
            data["c_t_prime"]["y"],
            CURVE
        )
        CM = Point(
            data["c_m"]["x"],
            data["c_m"]["y"],
            CURVE
        )

        sk_dst_inv = pow(self.key_manager.private_key, -1, CURVE.q)
        M = CM - (sk_dst_inv * CT_prime)

        hM_computed = hashlib.sha256(
            M.x.to_bytes(32, "big") + M.y.to_bytes(32, "big")
        ).hexdigest()

        if hM_computed == data["hM"]:
            print(f"[{poc_dt_id}] Message integrity verified successfully")
        else:
            print(f"[{poc_dt_id}] Integrity check failed")
        
        # right now count has to be hardcoded, can be sent as part of payload in future
        m = decode_reals(M, 4)
        print(f"[{poc_dt_id}] Decrypted data: {m}")

        Q = [derive_Gi(i) for i in range(1, len(m) + 1)]

        e = hash_to_scalar(b"".join(
            Q_i.x.to_bytes(32, "big") + Q_i.y.to_bytes(32, "big") for Q_i in Q
        ) + R.x.to_bytes(32, "big") + R.y.to_bytes(32, "big") + C.x.to_bytes(32, "big") + C.y.to_bytes(32, "big") + self.key_manager.P.x.to_bytes(32, "big") + self.key_manager.P.y.to_bytes(32, "big"))

        left_side = None
        for i, vi in enumerate(v, start=1):
            Qi = Q[i-1]
            term = vi * Qi
            left_side = term if left_side is None else left_side + term
        
        left_side = left_side + u * self.key_manager.P

        right_side = R + (e % CURVE.q) * C
        if left_side == right_side:
            print(f"[{poc_dt_id}] Signature verification successful")
        else:
            print(f"[{poc_dt_id}] Signature verification failed")

    def start_receiver_thread(self):
        recv_thread = threading.Thread(
            target=self.start,
            daemon=True
        )
        recv_thread.start()

    

if __name__ == "__main__":
    km = KeyManager()
    km.get_keys()
    sk = km.private_key
    public_key = km.public_key

    print(f"[{poc_dt_id}] Private Key: {sk}")
    print(f"[{poc_dt_id}] Public Key: ({public_key.x}, {public_key.y})")

    comms = CommunicationManager(km)
    comms.start_receiver_thread()

    while True:
        dest = input("Destination DT ID: ")
        params = [4.5678, -9.1011, 12.1314, 5.123]
        comms.send_data_to_edge(params, dest)
