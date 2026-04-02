from fastecdsa.curve import P384
from dotenv import load_dotenv
import secrets
import socket
import json
import os

load_dotenv()

DT_IDS = []
DT_REGISTRY = {}
KEYS_PORT = int(os.getenv("KEYS_PORT", 8080))
EDGE_KEYS_PORT = int(os.getenv("EDGE_KEYS_PORT", 8083))
EDGE_IP = os.getenv("EDGE_IP")


class TA:
    def __init__(self):
        self.curve = P384
        self.P = self.curve.G          # Generator point
        self.q = self.curve.q          # Curve order
        self.dt_keys = {}

    def generate_key_pair(self):
        """
        Generates a public-private key pair for POC digital twin.
        """
        sk_org = secrets.randbelow(self.q-1) + 1
        pk_org = sk_org * self.P
        return sk_org, pk_org

    def generate_key_edge(self, sk_org, sk_dst):
        """
        Generates a unidirectional re-encryption key for the edge server.
        """
        sk_org_inv= pow(sk_org, -1, self.q)
        reenc_key = (sk_org_inv * sk_dst) % self.q

        return reenc_key

    def send_keys(self):
        """
        Sends the generated keys to the specified recipient.
        """
        # change this as a server that listens for connections from the client and sends the keys when a connection is established
        # Initially the client sends a request with its IP address and it's DT ID, then the TA sends the keys to the client
        # We add entries into the DT registry as well as write it into .env file so that the client can read it when it starts up
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(('', KEYS_PORT))
            server.listen()
            print(f"[TA] Listening for connections on port {KEYS_PORT}...")
            while True:
                conn, addr = server.accept()
                with conn:
                    print(f"[TA] Connection established with {addr}")
                    data = ""
                    while True:
                        chunk = conn.recv(4096).decode("utf-8")
                        if not chunk:
                            break
                        data += chunk
                        if "\n" in data:
                            break
                    if not data:
                        print(f"[TA] No data received from {addr}")
                        continue
                    try:
                        request = json.loads(data.strip())
                        print(f"[TA] Received request: {request}")
                        DT_REGISTRY[request.get("dt_id")] = addr[0]
                        DT_IDS.append(request.get("dt_id"))
                        sk, pk = self.generate_key_pair()
                        self.dt_keys[request.get("dt_id")] = (sk, pk)
                        key_json = {
                            "curve": "secp256k1",
                            "dt_id": request.get("dt_id"),
                            "sk_org": sk,
                            "pk_org": {
                                "x": pk.x,
                                "y": pk.y
                            }
                        }
                        response = json.dumps(key_json) + "\n"
                        conn.sendall(response.encode("utf-8"))
                        print(f"[TA] Keys sent to {addr[0]}:{KEYS_PORT}")
                        self.send_keys_to_edge(request.get("dt_id"), EDGE_IP)
                    except json.JSONDecodeError:
                        print(f"[TA] Failed to decode JSON from {addr}: {data}")
        
        # try:
        #     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #     s.connect((recipient_ip, KEYS_PORT))
        #     print(f"[TA] Connected to {recipient_ip}:{KEYS_PORT}. Sending keys...")
        #     s.sendall((json.dumps(key_json) + "\n").encode("utf-8"))
        #     print(f"[TA] Keys sent to {recipient_ip}:{KEYS_PORT}")
        # except ConnectionRefusedError:
        #     print(f"[TA] Could not connect to {recipient_ip}:{KEYS_PORT}")
        # finally:
        #     s.close()
        
    def send_keys_to_edge(self, dt_id, edge_ip):
        """
        Sends the re-encryption keys to the edge server.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((edge_ip, EDGE_KEYS_PORT))
            print(f"[TA] Connected to {edge_ip}:{EDGE_KEYS_PORT}. Sending keys...")
            reenc_payload = {"reenc_keys": [], "dt_id": dt_id, "dt_ip": DT_REGISTRY[dt_id]}
            # iterate through the DT registry and generate re-encryption keys for the edge server
            for dst_id in DT_IDS:
                if dst_id == dt_id:
                    continue
                rk_to_dst = self.generate_key_edge(
                    self.dt_keys[dt_id][0],
                    self.dt_keys[dst_id][0]
                )
                reenc_payload["reenc_keys"].append({
                    "from": dt_id,
                    "to": dst_id,
                    "rk": rk_to_dst,
                })

                rk_from_dst = self.generate_key_edge(
                    self.dt_keys[dst_id][0],
                    self.dt_keys[dt_id][0]
                )
                reenc_payload["reenc_keys"].append({
                    "from": dst_id,
                    "to": dt_id,
                    "rk": rk_from_dst,
                })


            s.sendall((json.dumps(reenc_payload) + "\n").encode("utf-8"))
            print(f"[TA] Keys sent to {EDGE_IP}:{EDGE_KEYS_PORT}")
        except ConnectionRefusedError:
            print(f"[TA] Could not connect to {EDGE_IP}:{EDGE_KEYS_PORT}")
        finally:
            s.close()

if __name__ == "__main__":
    ta = TA()
    ta.send_keys()