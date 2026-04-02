import sqlite3

DB_PATH = "dt_keys.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Enable good defaults
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")

    # Keypairs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keypairs (
            dt_id TEXT PRIMARY KEY,
            sk TEXT,
            pk_x TEXT,
            pk_y TEXT
        )
    """)

    # Index (optional but good practice)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_dt_id
        ON keypairs(dt_id)
    """)

    conn.commit()
    conn.close()

    print("[DB] Digital Twin keypairs DB initialized.")


def store_keypair(dt_id, key_pair):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO keypairs (dt_id, sk, pk_x, pk_y)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(dt_id)
        DO UPDATE SET
            sk=excluded.sk,
            pk_x=excluded.pk_x,
            pk_y=excluded.pk_y
    """, (
        dt_id,
        str(key_pair["sk_org"]),
        str(key_pair["pk_org"]["x"]),
        str(key_pair["pk_org"]["y"])
    ))

    conn.commit()
    conn.close()


def get_keypair(dt_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT sk, pk_x, pk_y
        FROM keypairs
        WHERE dt_id=?
    """, (dt_id,))

    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "sk": row[0],
            "pk": {
                "x": row[1],
                "y": row[2]
            }
        }
    return None