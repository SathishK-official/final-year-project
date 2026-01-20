#!/usr/bin/env python3
"""
BRAMKA AI - Setup Verification Script
Tests all components to ensure proper installation
"""

import os
import sys
from pathlib import Path

def print_header(text):
    """Print formatted header"""
    print(f"\n{'='*70}")
    print(f"  {text}")
    print('='*70)

def test_python_version():
    """Test Python version"""
    print("\n🐍 Testing Python Version...")
    version = sys.version_info
    print(f"   Python {version.major}.{version.minor}.{version.micro}")
    
    if version.major == 3 and version.minor >= 10:
        print("   ✅ Python version is compatible")
        return True
    else:
        print("   ❌ Python 3.10+ required")
        return False

def test_imports():
    """Test critical package imports"""
    print("\n📦 Testing Package Imports...")
    
    packages = {
        'groq': 'Groq API Client',
        'chromadb': 'ChromaDB Vector Database',
        'fastapi': 'FastAPI Web Framework',
        'streamlit': 'Streamlit Dashboard',
        'sqlalchemy': 'SQLAlchemy ORM',
        'pydantic': 'Pydantic Data Validation',
        'yaml': 'PyYAML',
        'dotenv': 'Python Dotenv',
        'loguru': 'Loguru Logging',
        'requests': 'Requests HTTP',
    }
    
    all_passed = True
    for package, description in packages.items():
        try:
            __import__(package)
            print(f"   ✅ {description:.<40} OK")
        except ImportError:
            print(f"   ❌ {description:.<40} MISSING")
            all_passed = False
    
    return all_passed

def test_environment():
    """Test environment variables"""
    print("\n🔐 Testing Environment Variables...")
    
    if not os.path.exists('.env'):
        print("   ❌ .env file not found")
        print("   💡 Copy .env.example to .env and add your API keys")
        return False
    
    from dotenv import load_dotenv
    load_dotenv()
    
    required_vars = {
        'GROQ_API_KEY': 'Groq API Key',
    }
    
    optional_vars = {
        'OLLAMA_BASE_URL': 'Ollama URL',
        'LOG_LEVEL': 'Log Level',
    }
    
    all_required = True
    for var, description in required_vars.items():
        value = os.getenv(var)
        if value and value != f'your_{var.lower()}_here':
            print(f"   ✅ {description:.<40} SET")
        else:
            print(f"   ❌ {description:.<40} NOT SET")
            all_required = False
    
    for var, description in optional_vars.items():
        value = os.getenv(var)
        if value:
            print(f"   ℹ️  {description:.<40} SET")
        else:
            print(f"   ⚠️  {description:.<40} NOT SET (optional)")
    
    return all_required

def test_config_files():
    """Test configuration files"""
    print("\n⚙️  Testing Configuration Files...")
    
    config_files = {
        'config/config.yaml': 'Main Configuration',
        'config/prompts.yaml': 'LLM Prompts',
    }
    
    all_exist = True
    for file_path, description in config_files.items():
        if os.path.exists(file_path):
            print(f"   ✅ {description:.<40} EXISTS")
        else:
            print(f"   ❌ {description:.<40} MISSING")
            all_exist = False
    
    return all_exist

def test_databases():
    """Test database connections"""
    print("\n💾 Testing Databases...")
    
    # Test SQLite
    try:
        import sqlite3
        db_path = 'data/sqlite/bramka.db'
        
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
            table_count = cursor.fetchone()[0]
            conn.close()
            print(f"   ✅ SQLite Database............. OK ({table_count} tables)")
        else:
            print("   ❌ SQLite Database............. NOT INITIALIZED")
            print("      Run: python scripts/init_database.py")
            return False
    except Exception as e:
        print(f"   ❌ SQLite Database............. ERROR: {e}")
        return False
    
    # Test ChromaDB
    try:
        import chromadb
        client = chromadb.PersistentClient(path="data/vector_db")
        collections = client.list_collections()
        print(f"   ✅ ChromaDB.................... OK ({len(collections)} collections)")
    except Exception as e:
        print(f"   ⚠️  ChromaDB.................... WARNING: {e}")
    
    return True

def test_directories():
    """Test required directories"""
    print("\n📁 Testing Directory Structure...")
    
    required_dirs = [
        'data/vector_db',
        'data/sqlite',
        'data/logs',
        'data/reports',
        'data/downloads',
        'config',
    ]
    
    all_exist = True
    for directory in required_dirs:
        if os.path.exists(directory):
            print(f"   ✅ {directory}")
        else:
            print(f"   ❌ {directory} - MISSING")
            all_exist = False
    
    return all_exist

def test_groq_api():
    """Test Groq API connection"""
    print("\n🤖 Testing Groq API Connection...")
    
    try:
        from dotenv import load_dotenv
        load_dotenv()
        
        api_key = os.getenv('GROQ_API_KEY')
        if not api_key or api_key == 'your_groq_api_key_here':
            print("   ⚠️  Groq API key not set")
            print("      Get free key at: https://console.groq.com/keys")
            return False
        
        from groq import Groq
        client = Groq(api_key=api_key)
        
        # Test with minimal request
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": "Say 'OK' if you can hear me"}],
            model="llama-3.1-70b-versatile",
            max_tokens=10,
        )
        
        if response.choices[0].message.content:
            print("   ✅ Groq API Connection......... OK")
            print(f"   ℹ️  Model: llama-3.1-70b-versatile")
            return True
        
    except Exception as e:
        print(f"   ❌ Groq API Connection......... FAILED")
        print(f"      Error: {e}")
        return False

def test_kali_tools():
    """Test Kali Linux tools availability"""
    print("\n🛠️  Testing Kali Tools...")
    
    tools = {
        'nmap': 'Network Scanner',
        'sqlmap': 'SQL Injection Tool',
        'hydra': 'Password Cracker',
        'john': 'Password Hash Cracker',
        'netcat': 'Network Utility',
    }
    
    import subprocess
    
    for tool, description in tools.items():
        try:
            result = subprocess.run(
                ['which', tool],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                print(f"   ✅ {description:.<30} {tool} found")
            else:
                print(f"   ⚠️  {description:.<30} {tool} not found")
        except:
            print(f"   ⚠️  {description:.<30} {tool} check failed")

def generate_report(results):
    """Generate final report"""
    print_header("VERIFICATION REPORT")
    
    total_tests = len(results)
    passed_tests = sum(1 for r in results.values() if r)
    
    print(f"\n📊 Results: {passed_tests}/{total_tests} tests passed")
    print("\nTest Summary:")
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {status} - {test_name}")
    
    if passed_tests == total_tests:
        print("\n" + "="*70)
        print("🎉 ALL TESTS PASSED! BRAMKA AI is ready to use!")
        print("="*70)
        print("\nNext steps:")
        print("1. Start development with Phase 3 (Core modules)")
        print("2. Or test the setup with a simple script")
        print("="*70)
        return True
    else:
        print("\n" + "="*70)
        print("⚠️  SOME TESTS FAILED")
        print("="*70)
        print("\nPlease fix the issues above before continuing.")
        print("="*70)
        return False

def main():
    """Main verification function"""
    print_header("BRAMKA AI - Setup Verification")
    print("This script will verify your installation is complete and working")
    
    results = {
        'Python Version': test_python_version(),
        'Package Imports': test_imports(),
        'Environment Variables': test_environment(),
        'Configuration Files': test_config_files(),
        'Directory Structure': test_directories(),
        'Databases': test_databases(),
        'Groq API': test_groq_api(),
    }
    
    # Optional test
    test_kali_tools()
    
    # Generate report
    all_passed = generate_report(results)
    
    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()
