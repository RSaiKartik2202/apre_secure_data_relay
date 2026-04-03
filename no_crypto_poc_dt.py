import os
import socket
import json
import secrets
import hashlib
import time
import threading
import random
import statistics
from dotenv import load_dotenv
from fastecdsa import curve
from fastecdsa.point import Point
from utils.encoding.koblitz import encode_reals, decode_reals
from utils.db.poc_dt_setup import init_db, store_keypair, get_keypair

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
        self.curve = curve.P384
        self.q = self.curve.q          # Curve order
        self.P = self.curve.G          # Generator point
        init_db()


    def recv_key_pair(self):
        """
        Receives the public-private key pair from trusted authority.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((TA_IP, KEYS_PORT))
                print(f"[{poc_dt_id}] Connected to TA at {TA_IP}:{KEYS_PORT}. Requesting key pair...")
                request_info = {
                    "dt_id": poc_dt_id,
                    "ip": os.getenv(f"{poc_dt_id}_IP", "unknown"),
                }
                s.sendall((json.dumps(request_info) + "\n").encode())
                print(f"[{poc_dt_id}] Sent key request to TA with info: {request_info}")

                buffer = ""
                while True:
                    chunk = s.recv(4096).decode("utf-8")
                    if not chunk:
                        break
                    buffer += chunk
                    if "\n" in buffer:
                        break

                if buffer.strip():
                    key_pair = json.loads(buffer.strip())
                    store_keypair(poc_dt_id, key_pair)
                    self.private_key = key_pair["sk_org"]
                    self.public_key = Point(key_pair["pk_org"]["x"], key_pair["pk_org"]["y"], curve.P384)
                    print(f"[{poc_dt_id}] Key pair received and stored in database")
        except Exception as e:
            print(f"[{poc_dt_id}] Failed to receive key pair from TA: {e}")


    
    def get_keys(self):
        """
        Retrieves the stored keys from the .env file or receives them from the trusted authority.
        """
        key_pair = get_keypair(poc_dt_id)
        if key_pair is None:
                self.recv_key_pair()
                return
        self.private_key = int(key_pair["sk"])
        pk_x = int(key_pair["pk"]["x"])
        pk_y = int(key_pair["pk"]["y"])
        self.public_key = Point(pk_x, pk_y, curve.P384)
        print(f"[{poc_dt_id}] Key pair loaded from database")


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


        M = encode_reals(data)
        print(f"[{poc_dt_id}] Encoded data point M: ({M.x}, {M.y})")
        coord_size = (self.key_manager.curve.q.bit_length() + 7) // 8
        hM = hashlib.sha384(
            b"M|" +
            M.x.to_bytes(coord_size, "big") +
            M.y.to_bytes(coord_size, "big")
        ).digest()

        print(f"[{poc_dt_id}] Hashed data point hM: {hM.hex()}")

        payload = {
            "src_dt_id": poc_dt_id,
            "dest_dt_id": dest_dt_id,
            "curve": "P384",
            "M": {
                "x": M.x,
                "y": M.y
            },
            "hM": hM.hex(),
            "Torg": time.time()
        }
        end_time = time.perf_counter()
        self.comp_times.append(end_time - start_time)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((EDGE_IP, EDGE_PORT))
            s.sendall((json.dumps(payload) + "\n").encode())
            print(f"[{poc_dt_id}] Sent data to edge server at {EDGE_IP}:{EDGE_PORT}")
            s.close()
        except ConnectionRefusedError:
            print(f"[{poc_dt_id}] Edge server not available")
            return
        return
    
    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("0.0.0.0", DATA_PORT))
            server.listen(5)
            print(f"[{poc_dt_id}] Listening for data from {EDGE_IP}:{EDGE_PORT}...")

            while True:
                conn, addr = server.accept()
                # if addr[0] != EDGE_IP:
                #     print(f"[{poc_dt_id}] Connection from unauthorized IP {addr[0]}. Closing connection.")
                #     conn.close()
                #     continue
                print(f"[{poc_dt_id}] Connection established with {addr}")
                thread = threading.Thread(target=self.handle_connection, args=(conn, addr))
                thread.start()

    def handle_connection(self, conn, addr):
        try:
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
                # beautify print the payload
                payload_str = json.dumps(payload, indent=2)
                print(f"[{poc_dt_id}] Received payload: {payload_str}")
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
        else:
            print(f"[{poc_dt_id}] Timestamp check passed: Tproxy={Tproxy}, current_time={time.time()}")

        CURVE = curve.P384
        M = Point(
            data["M"]["x"],
            data["M"]["y"],
            CURVE
        )
        print(f"[{poc_dt_id}] Decrypted point M: ({M.x}, {M.y})")

        coord_size = (CURVE.q.bit_length() + 7) // 8

        hM_computed = hashlib.sha384(
            b"M|" +
            M.x.to_bytes(coord_size, "big") +
            M.y.to_bytes(coord_size, "big")
        ).digest()

        if hM_computed == bytes.fromhex(data["hM"]):
            print(f"[{poc_dt_id}] Message integrity verified successfully")
        else:
            print(f"[{poc_dt_id}] Integrity check failed")
        
        # right now count has to be hardcoded, can be sent as part of payload in future
        m = decode_reals(M, 7)
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
            filename = f"no_crypto_stats_{poc_dt_id}.json"
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

    print(f"[{poc_dt_id}] Public Key: ({public_key.x}, {public_key.y})")

    comms = CommunicationManager(km)
    comms.start_receiver_thread()

    try:
        ITER_CNT = int(input("Number of iterations: "))
        dest = input("Destination DT ID: ")
        for _ in range(ITER_CNT):
            params = [round(random.randint(-5000, 5000) / 100, 4) for _ in range(7)]
            print(f"[{poc_dt_id}] Sending data: {params} to {dest}")
            comms.send_data_to_edge(params, dest)
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[{poc_dt_id}] Interrupted by user. Processing stats...")
    finally:
        comms.save_and_print_stats()
