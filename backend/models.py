"""
TaskFlowr - Database Models
INTENTIONALLY INSECURE: This file contains multiple security anti-patterns.
"""

import sqlite3
import os
import hashlib

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'taskflowr.db')


def get_db():
    """Get a raw SQLite connection.
    INTENTIONALLY INSECURE: No connection pooling, no ORM protection.
    TODO: Use SQLAlchemy ORM with parameterized queries.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with tables and seed data.
    INTENTIONALLY INSECURE: Passwords stored with weak hashing.
    TODO: Use bcrypt with proper salt rounds.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            department TEXT DEFAULT 'general',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            session_token TEXT,
            reset_token TEXT
        )
    ''')

    # Create tasks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            priority TEXT DEFAULT 'medium',
            assigned_to INTEGER,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (assigned_to) REFERENCES users(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')

    # Create reimbursements table (for business logic flaw demo)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reimbursements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            approved_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (approved_by) REFERENCES users(id)
        )
    ''')

    # Create audit_log table (but we won't actually use it properly)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            user_id INTEGER,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # INTENTIONALLY INSECURE: Seed users with MD5-hashed passwords
    # TODO: Use bcrypt with cost factor >= 12
    seed_users = [
        ('admin', 'admin@taskflowr.io', hashlib.md5('admin123'.encode()).hexdigest(), 'admin', 'engineering'),
        ('manager1', 'manager@taskflowr.io', hashlib.md5('manager123'.encode()).hexdigest(), 'manager', 'engineering'),
        ('john', 'john@taskflowr.io', hashlib.md5('password123'.encode()).hexdigest(), 'user', 'marketing'),
        ('jane', 'jane@taskflowr.io', hashlib.md5('letmein'.encode()).hexdigest(), 'user', 'design'),
        ('bob', 'bob@taskflowr.io', hashlib.md5('bob2024'.encode()).hexdigest(), 'user', 'engineering'),
    ]

    for user in seed_users:
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password, role, department) VALUES (?, ?, ?, ?, ?)",
                user
            )
        except sqlite3.IntegrityError:
            pass  # User already exists

    # Seed tasks
    seed_tasks = [
        ('Fix login page CSS', 'The login button is misaligned on mobile', 'in_progress', 'high', 3, 2),
        ('Update API docs', 'Swagger docs are outdated', 'pending', 'medium', 4, 2),
        ('Deploy v2.1', 'Push new release to staging', 'pending', 'high', 5, 1),
        ('Review PR #42', 'Security review of auth module', 'pending', 'low', 3, 2),
        ('Database backup script', 'Automate daily backups', 'completed', 'high', 5, 1),
        ('Onboard new intern', 'Setup accounts and permissions', 'pending', 'medium', 4, 2),
    ]

    for task in seed_tasks:
        try:
            cursor.execute(
                "INSERT INTO tasks (title, description, status, priority, assigned_to, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                task
            )
        except sqlite3.IntegrityError:
            pass

    # Seed reimbursements
    seed_reimbursements = [
        (2, 250.00, 'Team lunch', 'pending', None),
        (3, 45.99, 'Office supplies', 'approved', 2),
        (4, 120.00, 'Conference ticket', 'pending', None),
    ]

    for reimb in seed_reimbursements:
        try:
            cursor.execute(
                "INSERT INTO reimbursements (user_id, amount, description, status, approved_by) VALUES (?, ?, ?, ?, ?)",
                reimb
            )
        except:
            pass

    conn.commit()
    conn.close()
    print("[*] Database initialized with seed data")
