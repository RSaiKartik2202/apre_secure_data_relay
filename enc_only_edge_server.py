import os
import socket
import json
import time
import threading
import statistics
from dotenv import load_dotenv
from fastecdsa import curve
from fastecdsa.point import Point
from utils.db.edge_db_setup import KeyStore

load_dotenv()

DESTINATION_REGISTRY = {}
DATA_RECEIVE_PORT = int(os.getenv("REAL_EDGE_PORT", 8084))
DATA_FORWARD_PORT = int(os.getenv("DATA_PORT", 8081))
KEYS_RECEIVE_PORT = int(os.getenv("EDGE_KEYS_PORT", 8083))
TA_IP = os.getenv("TA_IP")

class KeyManager:
    def __init__(self):
        self.ks = KeyStore()
        self.lock = threading.Lock()
    
    def handle_client(self, conn, addr):
        with conn:
            print("[EDGE_SERVER] Connected by", addr)
            buffer = ""
            while True:
                chunk = conn.recv(4096).decode("utf-8")
                if not chunk:
                    break
                buffer += chunk
                if "\n" in buffer:
                    break
            reenc_key_data = json.loads(buffer.strip())
            print(f"[EDGE_SERVER] Received re-encrypted keys for {reenc_key_data['dt_id']}:{reenc_key_data['dt_ip']} from TA")
            with self.lock:
                DESTINATION_REGISTRY[reenc_key_data["dt_id"]] = reenc_key_data["dt_ip"]
                self.ks.store_keys(reenc_key_data)
            print(f"[EDGE_SERVER] Updated DESTINATION_REGISTRY: {DESTINATION_REGISTRY}")
            print(f"[EDGE_SERVER] Stored re-encryption keys for {reenc_key_data['dt_id']} in Database")



    def recv_reencrypted_key(self):
        """
        Receives the re-encrypted key from trusted authority.
        """
        sources = self.ks.get_all_sources()
        if sources:
            print("[EDGE_SERVER] Existing sources in DB:")
            for from_id, from_ip in sources:
                print(f"  - {from_id} at {from_ip}")
                DESTINATION_REGISTRY[from_id] = from_ip
        
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("0.0.0.0", KEYS_RECEIVE_PORT))
            server.listen(5)
            print("[EDGE_SERVER] Waiting for re-encryption keys from Trusted Authority...")
            while True:
                conn, addr = server.accept()
                # if addr[0] != TA_IP:
                #     print(f"[EDGE_SERVER] Connection from unauthorized IP {addr[0]}. Closing connection.")
                #     conn.close()
                #     continue
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon = True).start()
                


class EdgeServer:
    def __init__(self):
        self.comp_times = []
        self.stats_lock = threading.Lock()
        self.ks = KeyStore()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("0.0.0.0", DATA_RECEIVE_PORT))
            server.listen(5)
            server.settimeout(1.0)
            print("[EDGE_SERVER] Listening for incoming data... Press Ctrl+C to stop.")

            while True:
                try:
                    conn, addr = server.accept()
                    thread = threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True)
                    thread.start()
                except socket.timeout:
                    continue

    def handle_connection(self, conn, addr):
        try:
            print("[EDGE_SERVER] Connection from", addr)
            buffer = ""

            while True:
                chunk = conn.recv(4096).decode("utf-8")
                if not chunk:
                    break
                buffer += chunk
                if "\n" in buffer:
                    break

            start_time = time.perf_counter()
            if buffer.strip():
                payload = json.loads(buffer.strip())
                payload_str = json.dumps(payload, indent=2)
                print("[EDGE_SERVER] Received payload:", payload_str)
                self.process_payload(payload)
        except Exception as e:
            print("[EDGE_SERVER] Error processing connection from", addr, ":", e)
        finally:
            end_time = time.perf_counter()
            with self.stats_lock:
                self.comp_times.append(end_time - start_time)
            conn.close()

    def process_payload(self, data):
        Torg = data["Torg"]
        if abs(time.time() - Torg) > 10:
            print("[EDGE_SERVER] Dropping message: stale timestamp")
            return
        else:
            print(f"[EDGE_SERVER] Timestamp check passed: Torg={Torg}, current_time={time.time()}")

        CT = Point(
            data["c_t"]["x"],
            data["c_t"]["y"],
            curve.P384
        )
        CM = Point(
            data["c_m"]["x"],
            data["c_m"]["y"],
            curve.P384
        )

        # Re-encryption: C_T' = rk * C_T
        src_id = data["src_dt_id"]
        dst_id = data["dest_dt_id"]

        renc_key_str = self.ks.get_key(src_id, dst_id)
        if renc_key_str is None:
            print(f"[EDGE_SERVER] No re-encryption key for {src_id} -> {dst_id}. Cannot process request.")
            return

        rk = int(renc_key_str)
        CT_prime = rk * CT
        print(f"[EDGE SERVER] Updated C_t' for {src_id} -> {dst_id} using re-encryption key. C_t': ({CT_prime.x}, {CT_prime.y})")
        print(f"[EDGE_SERVER] Re-encryption successful for {src_id} -> {dst_id}. Forwarding to destination...")

        dst_id = data["dest_dt_id"]
        if dst_id not in DESTINATION_REGISTRY:
            print("[EDGE_SERVER] Unknown destination:", dst_id)
            return


        self.forward_to_destination(
            dst_id,
            CT_prime,
            CM,
            data,
            time.time()
        )

    def forward_to_destination(self, dst_id, CT_prime, CM, data, Tproxy):
        dest_ip = DESTINATION_REGISTRY[dst_id]

        payload = {
            "curve": "P384",
            "c_t_prime": {
                "x": CT_prime.x,
                "y": CT_prime.y
            },
            "c_m": {
                "x": CM.x,
                "y": CM.y
            },
            "hM": data["hM"],
            "Tproxy": Tproxy
        }

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # print(f"[EDGE_SERVER] Connecting to {dst_id} at {dest_ip}:{DATA_FORWARD_PORT}...")
            s.connect((dest_ip, DATA_FORWARD_PORT))
            # print(f"[EDGE_SERVER] Connected to {dst_id} at {dest_ip}:{DATA_FORWARD_PORT}. Forwarding re-encrypted data...")
            s.sendall((json.dumps(payload) + "\n").encode())
        print(f"[EDGE_SERVER] Forwarded re-encrypted data to {dst_id}")

    def save_and_print_stats(self):
        with self.stats_lock:
            if not self.comp_times:
                print("\n[EDGE_SERVER] No data collected.")
                return

            # Convert to ms
            raw_ms = [t * 1000 for t in self.comp_times]
            avg = statistics.mean(raw_ms)
            std = statistics.stdev(raw_ms) if len(raw_ms) > 1 else 0

            print(f"\n" + "="*40)
            print(f" EDGE SERVER FINAL BENCHMARKS ")
            print(f"="*40)
            print(f"Total Requests: {len(raw_ms)}")
            print(f"Average:        {avg:.4f} ms")
            print(f"Std Dev:        {std:.4f} ms")
            print(f"Max Latency:    {max(raw_ms):.2f} ms")
            print(f"="*40)

            # Export to JSON
            output = {
                "role": "Edge Server",
                "timestamp": time.ctime(),
                "summary": {"avg_ms": avg, "std_ms": std, "count": len(raw_ms)},
                "raw_data_ms": raw_ms
            }
            with open("enc_only_stats_edge.json", "w") as f:
                json.dump(output, f, indent=4)
            print("[EDGE_SERVER] Results saved to enc_only_stats_edge.json")
        


if __name__ == "__main__":
    km = KeyManager()
    edge = EdgeServer()
    threading.Thread(target=km.recv_reencrypted_key, daemon=True).start()
    try:
        edge.start()
    except KeyboardInterrupt:
        print("\n[EDGE_SERVER] Shutting down...")
    finally:
        edge.save_and_print_stats()
        time.sleep(1)