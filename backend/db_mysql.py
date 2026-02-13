"""
TaskFlowr - MySQL GameServer Connection
INTENTIONALLY INSECURE: Connects to remote CTF database with vulnerable queries.

This module provides connection to the GameServer MySQL database that contains:
- users: For authentication and SQL truncation attacks
- secrets: For SQL injection vulnerabilities  
- messages: For IDOR vulnerabilities
- coupons: For race condition vulnerabilities
"""

import pymysql
import os
from contextlib import contextmanager

MYSQL_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'localhost'), 
    'port': int(os.getenv('MYSQL_PORT', 3306)),
    'user': os.getenv('MYSQL_USER', 'ctop_user'),
    'password': os.getenv('MYSQL_PASSWORD', 'ctop_secure_2024'),
    'database': os.getenv('MYSQL_DATABASE', 'ctop_university'),
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}


def get_mysql_connection():
    """
    Get a MySQL connection to the GameServer CTF database.
    
    INTENTIONALLY INSECURE: No connection pooling, no retry logic.
    TODO: Use connection pooling (e.g., DBUtils) for production.
    
    Returns:
        pymysql.Connection: Active MySQL connection
    """
    try:
        connection = pymysql.connect(**MYSQL_CONFIG)
        return connection
    except pymysql.MySQLError as e:
        print(f"[ERROR] Failed to connect to GameServer MySQL: {e}")
        raise


@contextmanager
def get_db_cursor(commit=False):
    """
    Context manager for database operations.
    
    Usage:
        with get_db_cursor(commit=True) as cursor:
            cursor.execute("INSERT INTO ...")
    
    Args:
        commit (bool): Whether to commit the transaction
        
    Yields:
        pymysql.cursors.Cursor: Database cursor
    """
    connection = get_mysql_connection()
    cursor = connection.cursor()
    try:
        yield cursor
        if commit:
            connection.commit()
    except Exception as e:
        connection.rollback()
        raise e
    finally:
        cursor.close()
        connection.close()


def test_connection():
    """
    Test the MySQL connection to GameServer.
    
    Returns:
        dict: Connection status and test query result
    """
    try:
        with get_db_cursor() as cursor:
            cursor.execute("SELECT VERSION() as version, DATABASE() as db")
            result = cursor.fetchone()
            return {
                "status": "connected",
                "mysql_version": result['version'],
                "database": result['db']
            }
    except Exception as e:
        return {
            "status": "failed",
            "error": str(e)
        }
