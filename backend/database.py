"""
CTOP University - Database Configuration
Connects to MySQL GameServer for production-like environment
"""

import os
from dotenv import load_dotenv
from typing import Optional, Dict, List, Any

# Use pymysql (already in requirements.txt) instead of mysql.connector
try:
    import pymysql
    import pymysql.cursors
    # Create compatibility shim for mysql.connector API
    class mysql:
        class connector:
            @staticmethod
            def connect(**kwargs):
                # Convert mysql.connector style config to pymysql
                pymysql_config = {
                    'host': kwargs.get('host', 'localhost'),
                    'port': kwargs.get('port', 3306),
                    'user': kwargs.get('user', 'root'),
                    'password': kwargs.get('password', ''),
                    'database': kwargs.get('database', ''),
                    'charset': kwargs.get('charset', 'utf8mb4'),
                    'autocommit': kwargs.get('autocommit', True),
                }
                return pymysql.connect(**pymysql_config)
    
    class Error(Exception):
        pass
    
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False
    pymysql = None
    print("[WARNING] pymysql not available - MySQL features will be disabled")

# Load environment variables
load_dotenv()

class DatabaseManager:
    """Manages MySQL GameServer connection only."""
    
    def __init__(self):
        self.mysql_config = {
            'host': os.environ.get('MYSQL_HOST', 'localhost'),
            'port': int(os.environ.get('MYSQL_PORT', 3306)),
            'user': os.environ.get('MYSQL_USER', 'ctop_user'),
            'password': os.environ.get('MYSQL_PASSWORD', 'ctop_secure_2024'),
            'database': os.environ.get('MYSQL_DATABASE', 'ctop_university'),
            'autocommit': True,
            'connection_timeout': 5
        }
        
    def get_mysql_connection(self):
        """Get MySQL connection (production database)."""
        if not MYSQL_AVAILABLE:
            print("[DATABASE] MySQL connector not available")
            return None
        try:
            connection = mysql.connector.connect(**self.mysql_config)
            return connection
        except Exception as e:
            print(f"[DATABASE] MySQL connection error: {e}")
            return None
    
    def execute_query(self, query: str, params: tuple = None) -> List[Dict]:
        """Execute MySQL query with SQL injection vulnerability."""
        connection = self.get_mysql_connection()
        if not connection:
            print(f"[DATABASE] MySQL connection failed - cannot execute query")
            return []
        
        try:
            # pymysql uses DictCursor instead of dictionary=True
            if pymysql and hasattr(pymysql, 'cursors'):
                cursor = connection.cursor(pymysql.cursors.DictCursor)
            else:
                cursor = connection.cursor(dictionary=True)
            
            # Vulnerable: String interpolation for SQL injection
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            if query.strip().upper().startswith('SELECT'):
                result = cursor.fetchall()
            else:
                connection.commit()
                result = [{'affected_rows': cursor.rowcount}]
            
            cursor.close()
            return result
            
        except Exception as e:
            print(f"[DATABASE] MySQL query error: {e}")
            return []
        finally:
            connection.close()
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Get user from MySQL GameServer."""
        query = f"SELECT * FROM users WHERE username = '{username}'"  # SQL injection vulnerability
        result = self.execute_query(query)
        return result[0] if result else None
    
    def log_activity_to_mysql(self, user_id: int, action: str, details: Dict):
        """Log user activity to MySQL GameServer."""
        query = f"""
            INSERT INTO user_activity (user_id, action, details, timestamp, ip_address)
            VALUES ({user_id}, '{action}', '{details}', NOW(), '{details.get('ip_address', 'unknown')}')
        """
        return self.execute_mysql_query(query)
    
    def sync_user_to_mysql(self, user_data: Dict) -> bool:
        """Sync user to MySQL GameServer."""
        query = f"""
            INSERT INTO users (username, email, role, created_at)
            VALUES ('{user_data['username']}', '{user_data['email']}', '{user_data['role']}', NOW())
            ON DUPLICATE KEY UPDATE email = '{user_data['email']}', role = '{user_data['role']}'
        """
        result = self.execute_mysql_query(query)
        return len(result) > 0

# Global database manager
db_manager = DatabaseManager()

# Legacy compatibility functions
def get_db():
    """Get MySQL connection (for existing code)."""
    return db_manager.get_mysql_connection()

def init_db():
    """Verify MySQL GameServer connection and list available tables."""
    mysql_conn = db_manager.get_mysql_connection()
    if not mysql_conn:
        print("[DATABASE] ERROR: Cannot connect to MySQL GameServer!")
        print("[DATABASE] Please check your MySQL configuration")
        return False
    
    try:
        cursor = mysql_conn.cursor()
        cursor.execute("SHOW TABLES")
        tables = [t[0] for t in cursor.fetchall()]
        print(f"[DATABASE] MySQL GameServer connected successfully")
        print(f"[DATABASE] Available tables: {', '.join(tables)}")
        cursor.close()
        mysql_conn.close()
        return True
        
    except Exception as e:
        print(f"[DATABASE] MySQL error: {e}")
        return False
