#!/usr/bin/env python3
"""
BRAMKA AI - Database Initialization Script
Creates and initializes ChromaDB and SQLite databases
"""

import os
import sys
from pathlib import Path
import sqlite3
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def create_directories():
    """Create necessary data directories"""
    directories = [
        'data/vector_db',
        'data/sqlite',
        'data/logs',
        'data/reports',
        'data/downloads/tools',
        'config'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def initialize_sqlite():
    """Initialize SQLite database with schema"""
    db_path = 'data/sqlite/bramka.db'
    
    print(f"\n📊 Initializing SQLite database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Attacks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            tool_used TEXT,
            success BOOLEAN NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            duration_seconds INTEGER,
            findings TEXT,
            command_used TEXT,
            error_message TEXT,
            metadata TEXT
        )
    ''')
    
    # Tools table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            category TEXT,
            install_path TEXT,
            install_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            version TEXT,
            repository_url TEXT,
            description TEXT,
            usage_count INTEGER DEFAULT 0,
            success_count INTEGER DEFAULT 0,
            last_used DATETIME,
            metadata TEXT
        )
    ''')
    
    # Targets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT UNIQUE NOT NULL,
            target_type TEXT,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_scanned DATETIME,
            os_fingerprint TEXT,
            open_ports TEXT,
            services TEXT,
            vulnerabilities TEXT,
            authorization_status TEXT DEFAULT 'pending',
            notes TEXT
        )
    ''')
    
    # Credentials table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            username TEXT,
            password TEXT,
            credential_type TEXT,
            source TEXT,
            discovered_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            verified BOOLEAN DEFAULT FALSE,
            notes TEXT
        )
    ''')
    
    # Metrics table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_name TEXT NOT NULL,
            metric_value REAL,
            metric_type TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            context TEXT
        )
    ''')
    
    # Audit log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            user TEXT DEFAULT 'system',
            target TEXT,
            details TEXT,
            severity TEXT
        )
    ''')
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_target ON attacks(target)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tools_name ON tools(name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_targets_target ON targets(target)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)')
    
    conn.commit()
    
    # Insert initial audit log entry
    cursor.execute('''
        INSERT INTO audit_log (action, details, severity)
        VALUES (?, ?, ?)
    ''', ('DATABASE_INITIALIZED', 'BRAMKA AI database initialized successfully', 'INFO'))
    
    conn.commit()
    conn.close()
    
    print("✅ SQLite database initialized successfully")
    print(f"   - Tables created: attacks, tools, targets, credentials, metrics, audit_log")
    print(f"   - Indexes created for performance")

def initialize_chromadb():
    """Initialize ChromaDB"""
    print("\n🧠 Initializing ChromaDB (Vector Database)...")
    
    try:
        import chromadb
        from chromadb.config import Settings
        
        # Create persistent client
        client = chromadb.PersistentClient(
            path="data/vector_db",
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Create collections
        collections_to_create = [
            {
                'name': 'tool_knowledge',
                'metadata': {'description': 'Tool usage patterns and knowledge'}
            },
            {
                'name': 'attack_patterns',
                'metadata': {'description': 'Attack patterns and strategies'}
            },
            {
                'name': 'exploit_database',
                'metadata': {'description': 'Known exploits and vulnerabilities'}
            }
        ]
        
        for collection_info in collections_to_create:
            try:
                collection = client.create_collection(
                    name=collection_info['name'],
                    metadata=collection_info['metadata']
                )
                print(f"   ✅ Created collection: {collection_info['name']}")
            except Exception as e:
                if "already exists" in str(e):
                    print(f"   ℹ️  Collection already exists: {collection_info['name']}")
                else:
                    print(f"   ❌ Error creating collection {collection_info['name']}: {e}")
        
        print("✅ ChromaDB initialized successfully")
        
    except ImportError:
        print("⚠️  ChromaDB not installed. Run: pip install chromadb")
    except Exception as e:
        print(f"❌ Error initializing ChromaDB: {e}")

def create_sample_data():
    """Create sample data for testing"""
    print("\n📝 Creating sample test data...")
    
    db_path = 'data/sqlite/bramka.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Sample tool
    cursor.execute('''
        INSERT OR IGNORE INTO tools (name, category, description, repository_url)
        VALUES (?, ?, ?, ?)
    ''', ('nmap', 'reconnaissance', 'Network exploration and security auditing', 'https://github.com/nmap/nmap'))
    
    # Sample metric
    cursor.execute('''
        INSERT INTO metrics (metric_name, metric_value, metric_type, context)
        VALUES (?, ?, ?, ?)
    ''', ('system_initialized', 1.0, 'status', 'Database initialization'))
    
    conn.commit()
    conn.close()
    
    print("✅ Sample data created")

def verify_installation():
    """Verify database installation"""
    print("\n🔍 Verifying installation...")
    
    # Check SQLite
    db_path = 'data/sqlite/bramka.db'
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get table count
        cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        table_count = cursor.fetchone()[0]
        
        print(f"✅ SQLite database exists with {table_count} tables")
        
        # Check audit log
        cursor.execute("SELECT COUNT(*) FROM audit_log")
        log_count = cursor.fetchone()[0]
        print(f"✅ Audit log has {log_count} entries")
        
        conn.close()
    else:
        print("❌ SQLite database not found")
    
    # Check ChromaDB
    if os.path.exists('data/vector_db'):
        print("✅ ChromaDB directory exists")
    else:
        print("⚠️  ChromaDB directory not found")
    
    # Check config directory
    if os.path.exists('config'):
        print("✅ Config directory exists")
        
        # Check for config files
        config_files = ['config.yaml', 'prompts.yaml']
        for config_file in config_files:
            if os.path.exists(f'config/{config_file}'):
                print(f"   ✅ {config_file} found")
            else:
                print(f"   ⚠️  {config_file} not found")
    else:
        print("❌ Config directory not found")
    
    # Check .env
    if os.path.exists('.env'):
        print("✅ .env file exists")
    else:
        print("⚠️  .env file not found - copy from .env.example")

def main():
    """Main initialization function"""
    print("=" * 70)
    print("BRAMKA AI - Database Initialization")
    print("=" * 70)
    
    try:
        create_directories()
        initialize_sqlite()
        initialize_chromadb()
        create_sample_data()
        verify_installation()
        
        print("\n" + "=" * 70)
        print("✅ INITIALIZATION COMPLETE!")
        print("=" * 70)
        print("\nNext steps:")
        print("1. Copy .env.example to .env")
        print("2. Add your Groq API key to .env")
        print("3. Run: python scripts/verify_setup.py")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n❌ Initialization failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
