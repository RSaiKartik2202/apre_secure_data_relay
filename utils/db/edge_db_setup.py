import sqlite3
import threading

DB_PATH = "reenc_keys.db"


class KeyStore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    # ---------------------------
    # DB Connection
    # ---------------------------
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")  # better concurrency
        return conn

    # ---------------------------
    # Initialize Tables
    # ---------------------------
    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Sources table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sources (
                    from_id TEXT PRIMARY KEY,
                    from_ip TEXT
                )
            """)

            # Re-encryption keys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reenc_keys (
                    from_id TEXT,
                    to_id TEXT,
                    rk TEXT,
                    PRIMARY KEY (from_id, to_id),
                    FOREIGN KEY (from_id) REFERENCES sources(from_id)
                )
            """)

            # Index for fast lookup
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_reenc_lookup
                ON reenc_keys(from_id, to_id)
            """)

            conn.commit()

    # ---------------------------
    # Insert / Update Data
    # ---------------------------
    def store_keys(self, reenc_key_data: dict):
        dt_id = reenc_key_data.get("dt_id")
        dt_ip = reenc_key_data.get("dt_ip")

        with self._lock:  # thread safety
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Upsert source
                cursor.execute("""
                    INSERT INTO sources (from_id, from_ip)
                    VALUES (?, ?)
                    ON CONFLICT(from_id)
                    DO UPDATE SET from_ip=excluded.from_ip
                """, (dt_id, dt_ip))

                # Upsert keys
                for item in reenc_key_data["reenc_keys"]:
                    from_id = item["from"]
                    to_id = item["to"]
                    rk = str(item["rk"])

                    cursor.execute("""
                        INSERT INTO reenc_keys (from_id, to_id, rk)
                        VALUES (?, ?, ?)
                        ON CONFLICT(from_id, to_id)
                        DO UPDATE SET rk=excluded.rk
                    """, (from_id, to_id, rk))

                conn.commit()

    # ---------------------------
    # Fetch Single Key
    # ---------------------------
    def get_key(self, from_id, to_id):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT rk FROM reenc_keys
                WHERE from_id=? AND to_id=?
            """, (from_id, to_id))

            row = cursor.fetchone()
            return row[0] if row else None

    # ---------------------------
    # Fetch Key + IP
    # ---------------------------
    def get_key_with_ip(self, from_id, to_id):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT rk, from_ip
                FROM reenc_keys
                JOIN sources USING (from_id)
                WHERE from_id=? AND to_id=?
            """, (from_id, to_id))

            row = cursor.fetchone()
            return {"rk": row[0], "from_ip": row[1]} if row else None

    # ---------------------------
    # Debug / View All
    # ---------------------------
    def get_all_keys(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT from_id, to_id, rk FROM reenc_keys
            """)

            return cursor.fetchall()
        
    # ---------------------------
    # Fetch all sources
    # ---------------------------
    def get_all_sources(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT from_id, from_ip FROM sources
            """)

            return cursor.fetchall()