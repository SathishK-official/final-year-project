"""
BRAMKA AI - SQLite Database Manager
Handles relational data storage for attacks, tools, sessions
"""

import sqlite3
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from src.utils.logger import get_logger
from src.utils.config_loader import get_config


class SQLiteManager:
    """
    SQLite database manager for structured data storage
    
    Stores:
    - Attack history and results
    - Tool metadata
    - Session information
    - User interactions
    - System logs
    """
    
    def __init__(self):
        self.logger = get_logger("SQLiteManager")
        self.config = get_config()
        
        db_path = self.config.get("database.sqlite.database_path", "data/sqlite/bramka.db")
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.connection: Optional[sqlite3.Connection] = None
        self._connect()
        self._initialize_tables()
        
        self.logger.info(f"✅ SQLite initialized: {self.db_path}")
    
    def _connect(self):
        """Establish database connection"""
        try:
            self.connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=10.0
            )
            self.connection.row_factory = sqlite3.Row
            self.logger.debug("📂 SQLite connection established")
        except Exception as e:
            self.logger.error(f"❌ SQLite connection failed: {e}")
            raise
    
    def _initialize_tables(self):
        """Create database schema"""
        schema = """
        -- Sessions table
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            commands_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active'
        );
        
        -- Interactions table
        CREATE TABLE IF NOT EXISTS interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            user_input TEXT NOT NULL,
            intent_category TEXT,
            intent_action TEXT,
            response_message TEXT,
            success BOOLEAN,
            created_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        );
        
        -- Attacks table
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            target TEXT NOT NULL,
            tool_used TEXT,
            parameters TEXT,
            result TEXT,
            success BOOLEAN,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        );
        
        -- Tools table
        CREATE TABLE IF NOT EXISTS tools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            category TEXT,
            installation_path TEXT,
            version TEXT,
            installed_at TEXT,
            last_used TEXT,
            usage_count INTEGER DEFAULT 0,
            success_rate REAL DEFAULT 0.0,
            metadata TEXT
        );
        
        -- Learning data table
        CREATE TABLE IF NOT EXISTS learning_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context TEXT NOT NULL,
            action_taken TEXT NOT NULL,
            outcome TEXT NOT NULL,
            success BOOLEAN,
            confidence REAL,
            created_at TEXT NOT NULL
        );
        
        -- Reports table
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            report_type TEXT NOT NULL,
            title TEXT,
            content TEXT,
            file_path TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        );
        
        -- System logs table
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL,
            module TEXT,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        
        -- Create indexes
        CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id);
        CREATE INDEX IF NOT EXISTS idx_attacks_session ON attacks(session_id);
        CREATE INDEX IF NOT EXISTS idx_attacks_type ON attacks(attack_type);
        CREATE INDEX IF NOT EXISTS idx_tools_name ON tools(name);
        CREATE INDEX IF NOT EXISTS idx_learning_success ON learning_data(success);
        """
        
        try:
            self.connection.executescript(schema)
            self.connection.commit()
            self.logger.debug("📋 Database schema initialized")
        except Exception as e:
            self.logger.error(f"❌ Schema initialization failed: {e}")
            raise
    
    def execute_query(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """
        Execute SQL query
        
        Args:
            query: SQL query string
            params: Query parameters
        
        Returns:
            Cursor object
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            return cursor
        except Exception as e:
            self.logger.error(f"❌ Query failed: {e}\nQuery: {query}")
            raise
    
    def fetch_all(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute query and fetch all results"""
        cursor = self.execute_query(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    def fetch_one(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        """Execute query and fetch one result"""
        cursor = self.execute_query(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def insert(self, table: str, data: Dict[str, Any]) -> int:
        """
        Insert data into table
        
        Args:
            table: Table name
            data: Dictionary of column: value
        
        Returns:
            Last inserted row ID
        """
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['?' for _ in data])
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        
        cursor = self.execute_query(query, tuple(data.values()))
        return cursor.lastrowid
    
    def update(self, table: str, data: Dict[str, Any], where: str, where_params: tuple = ()) -> int:
        """
        Update table rows
        
        Args:
            table: Table name
            data: Dictionary of column: value to update
            where: WHERE clause
            where_params: Parameters for WHERE clause
        
        Returns:
            Number of affected rows
        """
        set_clause = ', '.join([f"{k} = ?" for k in data.keys()])
        query = f"UPDATE {table} SET {set_clause} WHERE {where}"
        
        params = tuple(data.values()) + where_params
        cursor = self.execute_query(query, params)
        return cursor.rowcount
    
    def delete(self, table: str, where: str, where_params: tuple = ()) -> int:
        """Delete rows from table"""
        query = f"DELETE FROM {table} WHERE {where}"
        cursor = self.execute_query(query, where_params)
        return cursor.rowcount
    
    def get_table_count(self, table: str) -> int:
        """Get row count for table"""
        result = self.fetch_one(f"SELECT COUNT(*) as count FROM {table}")
        return result['count'] if result else 0
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.logger.info("🔒 SQLite connection closed")


# Testing
if __name__ == "__main__":
    from src.utils.logger import setup_logger
    
    setup_logger(log_level="INFO")
    
    db = SQLiteManager()
    
    # Test insert
    session_id = db.insert("sessions", {
        "session_id": "test_123",
        "started_at": datetime.now().isoformat(),
        "status": "active"
    })
    print(f"✅ Session inserted: ID {session_id}")
    
    # Test fetch
    sessions = db.fetch_all("SELECT * FROM sessions WHERE session_id = ?", ("test_123",))
    print(f"✅ Fetched {len(sessions)} sessions")
    
    # Test counts
    for table in ["sessions", "interactions", "attacks", "tools"]:
        count = db.get_table_count(table)
        print(f"📊 {table}: {count} rows")
    
    db.close()
