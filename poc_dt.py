import os
import socket
import json
import secrets
import hashlib
import time
import threading
import random
import csv
import uuid
import statistics
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
            """if addr[0] != TA_IP:
                print(f"[{poc_dt_id}] Connection from unauthorized IP {addr[0]}. Closing connection.")
                conn.close()
                return"""""
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
        self.comp_times = []
        self.recv_comp_times = []
        self.stats_lock = threading.Lock()

    def send_data_to_edge(self, data: bytes, dest_dt_id):
        """
        Communicates with the edge server to relay encrypted data.
        """
        start_time = time.perf_counter()
        
        cm = CryptoManager(self.key_manager)
        c_t, c_m, hM = cm.encrypt_data(data)

        request_id = str(uuid.uuid4())

        payload = {
            "request_id": request_id,
            "src_dt_id": poc_dt_id,
            "dest_dt_id": dest_dt_id,
            "curve": "secp256k1",
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
        end_time = time.perf_counter()
        self.comp_times.append(end_time - start_time)
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
                """if addr[0] != EDGE_IP:
                    print(f"[{poc_dt_id}] Connection from unauthorized IP {addr[0]}. Closing connection.")
                    conn.close()
                    continue"""
                thread = threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True)
                thread.start()

    def handle_connection(self, conn, addr):
        try:
            print(f"[{poc_dt_id}] Connection from", addr)
            buffer = ""

            while True:
                chunk = conn.recv(4096).decode("utf-8")
                if not chunk:
                    break
                buffer += chunk
                if "\n" in buffer:
                    break
            
            recv_start_time = time.perf_counter()
            if buffer.strip():
                payload = json.loads(buffer.strip())
                self.decrypt_and_verify(payload)
        except Exception as e:
            print(f"[{poc_dt_id}] Error handling connection: {e}")
        finally:
            conn.close()
            recv_end_time = time.perf_counter()
            with self.stats_lock:
                self.recv_comp_times.append(recv_end_time - recv_start_time)

    def decrypt_and_verify(self, data):
        Tproxy = data["Tproxy"]
        if abs(time.time() - Tproxy) > 10:
            print(f"[{poc_dt_id}] Dropping message: stale timestamp")
            return

        CURVE = curve.secp256k1
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
            

    def start_receiver_thread(self):
        recv_thread = threading.Thread(
            target=self.start,
            daemon=True
        )
        recv_thread.start()

    
    def save_and_print_stats(self):
        """
        Processes both Sending and Receiving stats, prints them, and saves to JSON.
        """
        with self.stats_lock:
            # Prepare data structure for JSON
            output_data = {
                "dt_id": poc_dt_id,
                "timestamp": time.ctime(),
                "sender_stats": {},
                "receiver_stats": {}
            }

            print(f"\n" + "="*40)
            print(f" FINAL BENCHMARKS FOR: {poc_dt_id} ")
            print(f"="*40)

            # Process Sender Data
            if self.comp_times:
                sender_ms = [t * 1000 for t in self.comp_times]
                avg_s = sum(sender_ms) / len(sender_ms)
                std_s = statistics.stdev(sender_ms) if len(sender_ms) > 1 else 0
                
                print(f"--- SENDER ROLE ---")
                print(f"Requests Sent: {len(sender_ms)}")
                print(f"Average:       {avg_s:.4f} ms")
                print(f"Std Dev:       {std_s:.4f} ms")
                
                output_data["sender_stats"] = {
                    "count": len(sender_ms),
                    "average_ms": avg_s,
                    "std_dev_ms": std_s,
                    "raw_ms": sender_ms
                }

            # Process Receiver Data
            if self.recv_comp_times:
                recv_ms = [t * 1000 for t in self.recv_comp_times]
                avg_r = sum(recv_ms) / len(recv_ms)
                std_r = statistics.stdev(recv_ms) if len(recv_ms) > 1 else 0
                
                print(f"\n--- RECEIVER ROLE ---")
                print(f"Requests Recv: {len(recv_ms)}")
                print(f"Average:       {avg_r:.4f} ms")
                print(f"Std Dev:       {std_r:.4f} ms")
                
                output_data["receiver_stats"] = {
                    "count": len(recv_ms),
                    "average_ms": avg_r,
                    "std_dev_ms": std_r,
                    "raw_ms": recv_ms
                }

            print("="*40)

            # Save to JSON
            filename = f"enc_only_stats_{poc_dt_id}.json"
            try:
                with open(filename, "w") as f:
                    json.dump(output_data, f, indent=4)
                print(f"Results saved to {filename}")
            except Exception as e:
                print(f"Failed to save JSON: {e}")

    

if __name__ == "__main__":
    km = KeyManager()
    km.get_keys()
    sk = km.private_key
    public_key = km.public_key

    print(f"[{poc_dt_id}] Private Key: {sk}")
    print(f"[{poc_dt_id}] Public Key: ({public_key.x}, {public_key.y})")

    comms = CommunicationManager(km)
    comms.start_receiver_thread()

    try:
        ITER_CNT = int(input("Number of iterations: "))
        dest = input("Destination DT ID: ")
        for _ in range(ITER_CNT):
            params = [round(random.randint(-5000, 5000) / 100, 4) for _ in range(4)]
            print(f"[{poc_dt_id}] Sending data: {params} to {dest}")
            comms.send_data_to_edge(params, dest)
            time.sleep(3)
    except KeyboardInterrupt:
        print(f"\n[{poc_dt_id}] Interrupted by user. Processing stats...")
    finally:
        comms.save_and_print_stats()