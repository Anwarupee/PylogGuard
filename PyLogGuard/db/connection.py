import mysql.connector
from mysql.connector import pooling

dbconfig = {
    "host": "localhost",
    "user": "root",
    "password": "12345",
    "database": "attack_logs_db"
}

connection_pool = pooling.MySQLConnectionPool(
    pool_name="mypool",
    pool_size=5,
    **dbconfig
)

def get_connection():
    """Get a connection from the pool"""
    return connection_pool.get_connection()