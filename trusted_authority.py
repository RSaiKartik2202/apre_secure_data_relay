from fastecdsa.curve import secp256k1
import secrets
import socket
import json

DT_IDS = ["DT_1", "DT_2"]
DT_REGISTRY = {
    "DT_1": {"port": 8081},
    "DT_2": {"port": 8082},
    "DT_3": {"port": 8086},
}
EDGE_PORT = 8083


class TA:
    def __init__(self):
        self.curve = secp256k1
        self.P = self.curve.G          # Generator point
        self.q = self.curve.q          # Curve order

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

    def send_keys(self, key_json, recipient_port):
        """
        Sends the generated keys to the specified recipient.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("localhost", recipient_port))
            s.sendall((json.dumps(key_json) + "\n").encode("utf-8"))
            print(f"[TA] Keys sent to port {recipient_port}")
        except ConnectionRefusedError:
            print(f"[TA] Could not connect to port {recipient_port}")
        finally:
            s.close()
        
        

if __name__ == "__main__":
    ta = TA()
    dt_keys = {}
    for dt_id in DT_IDS:
        sk, pk = ta.generate_key_pair()
        dt_keys[dt_id] = (sk, pk)
        ta.send_keys(
            {
                "curve": "secp256k1",
                "dt_id": dt_id,
                "sk_org": sk,
                "pk_org": {
                    "x": pk.x,
                    "y": pk.y
                }
            },
            DT_REGISTRY[dt_id]["port"]
        )

    reenc_payload = {"reenc_keys": []}
    for org in DT_IDS:
        for dst in DT_IDS:
            if org == dst:
                continue
            rk = ta.generate_key_edge(
                dt_keys[org][0],
                dt_keys[dst][0]
            )
            reenc_payload["reenc_keys"].append({
                "from": org,
                "to": dst,
                "rk": rk
            })

    ta.send_keys(reenc_payload, EDGE_PORT)