from db.connection import get_connection

def verify():
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT DATABASE(), USER();")
        print("Python -> SELECT DATABASE(), USER():", cur.fetchone())
        cur.execute("SELECT COUNT(*) FROM logs;")
        print("Python -> COUNT logs:", cur.fetchone()[0])
        cur.execute("SELECT log_id, source_ip, status, created_at, created_by FROM logs ORDER BY created_at DESC LIMIT 10;")
        rows = cur.fetchall()
        print("Python -> sample rows (up to 10):")
        for r in rows:
            print(" ", r)
        cur.close()
    finally:
        conn.close()

if __name__ == "__main__":
    verify()
