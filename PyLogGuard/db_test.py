from db.connection import get_connection
from datetime import datetime

def test_insert():
    conn = get_connection()
    cursor = conn.cursor()

    query = """
    INSERT INTO logs (source_ip, attack_id, status, details, created_at, created_by)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    data = ("192.168.1.10", 1, "Detected", "Test log entry", datetime.now(), 1)

    cursor.execute(query, data)
    conn.commit()
    print("Inserted log_id:", cursor.lastrowid)

    cursor.execute("SELECT * FROM logs ORDER BY log_id DESC LIMIT 1;")
    row = cursor.fetchone()
    print("Latest log entry:", row)

    cursor.close()
    conn.close()

if __name__ == "__main__":
    test_insert()