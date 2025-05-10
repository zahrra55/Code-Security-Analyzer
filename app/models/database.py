import sqlite3
import json
import logging
from typing import Dict, Any, List
from flask import current_app
import threading
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class DatabaseConnection:
    _instance = None
    _pool = []
    _lock = threading.Lock()
    _max_connections = 5
    _db_path = None

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(DatabaseConnection, cls).__new__(cls)
        return cls._instance

    def init_app(self, app):
        """Initialize the database connection with the app context."""
        self._db_path = app.config['DATABASE_URL'].replace('sqlite:///', '')

    @contextmanager
    def get_connection(self):
        """Get a database connection from the pool with proper cleanup."""
        conn = None
        try:
            with self._lock:
                if not self._pool:
                    if not self._db_path:
                        raise RuntimeError("Database not initialized. Call init_app first.")
                    conn = sqlite3.connect(self._db_path, check_same_thread=False)
                    conn.row_factory = sqlite3.Row
                    self._pool.append(conn)
                conn = self._pool[0]
            yield conn
        except Exception as e:
            logger.error(f"Error getting database connection: {e}")
            if conn:
                self._close_connection(conn)
            raise
        finally:
            if conn:
                conn.commit()

    def _close_connection(self, conn):
        """Close a database connection and remove it from the pool."""
        try:
            with self._lock:
                if conn in self._pool:
                    self._pool.remove(conn)
                conn.close()
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")

    def close_all(self):
        """Close all database connections in the pool."""
        with self._lock:
            for conn in self._pool:
                try:
                    conn.close()
                except Exception as e:
                    logger.error(f"Error closing connection: {e}")
            self._pool.clear()

def init_db():
    """Initialize the SQLite database with optimized schema."""
    try:
        with DatabaseConnection().get_connection() as conn:
            cursor = conn.cursor()
            
            # Create analysis results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    language TEXT NOT NULL,
                    prediction INTEGER,
                    fixed_code TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    code_hash TEXT UNIQUE,
                    vulnerabilities TEXT,
                    severity_counts TEXT,
                    execution_time REAL
                )
            """)
            
            # Create dependency vulnerabilities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dependency_vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    package TEXT NOT NULL,
                    version TEXT NOT NULL,
                    vulnerability TEXT NOT NULL,
                    fix TEXT,
                    severity TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES analysis_results (id) ON DELETE CASCADE
                )
            """)
            
            # Create indexes separately after tables are created
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_code_hash ON analysis_results(code_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON analysis_results(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_language ON analysis_results(language)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_id ON dependency_vulnerabilities(analysis_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_package ON dependency_vulnerabilities(package)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON dependency_vulnerabilities(created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_language ON analysis_results(language, timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dep_vuln_package ON dependency_vulnerabilities(package, version)")
            
            conn.commit()
            logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise

def save_analysis_result(
    filename: str,
    language: str,
    prediction: int,
    fixed_code: str,
    code_hash: str,
    vulnerabilities: List[Dict[str, Any]],
    severity_counts: Dict[str, int],
    execution_time: float
) -> int:
    """Save analysis results to the database with improved error handling."""
    try:
        with DatabaseConnection().get_connection() as conn:
            cursor = conn.cursor()
            
            # Convert vulnerabilities to JSON
            vuln_json = json.dumps(vulnerabilities)
            severity_json = json.dumps(severity_counts)
            
            cursor.execute("""
                INSERT OR REPLACE INTO analysis_results (
                    filename, language, prediction, fixed_code, code_hash,
                    vulnerabilities, severity_counts, execution_time
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                filename, language, prediction, fixed_code, code_hash,
                vuln_json, severity_json, execution_time
            ))
            
            return cursor.lastrowid
            
    except Exception as e:
        logger.error(f"Error saving analysis result: {e}")
        raise

def save_dependency_vulnerabilities(
    analysis_id: int,
    vulnerabilities: List[Dict[str, Any]]
) -> None:
    """Save dependency vulnerabilities to the database with improved error handling."""
    try:
        with DatabaseConnection().get_connection() as conn:
            cursor = conn.cursor()
            
            for vuln in vulnerabilities:
                cursor.execute("""
                    INSERT INTO dependency_vulnerabilities (
                        analysis_id, package, version, vulnerability, fix, severity
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    analysis_id,
                    vuln['package'],
                    vuln['version'],
                    vuln['vulnerability'],
                    vuln.get('fix', ''),
                    vuln.get('severity', 'unknown')
                ))
            
    except Exception as e:
        logger.error(f"Error saving dependency vulnerabilities: {e}")
        raise

def get_analysis_result(code_hash: str) -> Dict[str, Any]:
    """Get analysis result from the database with improved error handling."""
    try:
        with DatabaseConnection().get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM analysis_results
                WHERE code_hash = ?
                ORDER BY timestamp DESC
                LIMIT 1
            """, (code_hash,))
            
            result = cursor.fetchone()
            if result:
                return dict(result)
            return None
            
    except Exception as e:
        logger.error(f"Error getting analysis result: {e}")
        raise

def get_dependency_vulnerabilities(analysis_id: int) -> List[Dict[str, Any]]:
    """Get dependency vulnerabilities from the database with improved error handling."""
    try:
        with DatabaseConnection().get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM dependency_vulnerabilities
                WHERE analysis_id = ?
                ORDER BY created_at DESC
            """, (analysis_id,))
            
            return [dict(row) for row in cursor.fetchall()]
            
    except Exception as e:
        logger.error(f"Error getting dependency vulnerabilities: {e}")
        raise 