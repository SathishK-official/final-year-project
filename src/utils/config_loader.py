"""
BRAMKA AI - Configuration Loader
Loads and validates configuration from YAML and environment variables
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from loguru import logger

class ConfigLoader:
    """Loads and manages configuration"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize configuration loader
        
        Args:
            config_path: Path to main config YAML file
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.prompts: Dict[str, Any] = {}
        
        # Load environment variables
        load_dotenv()
        
        # Load configurations
        self._load_config()
        self._load_prompts()
        self._override_with_env()
    
    def _load_config(self):
        """Load main configuration from YAML"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
            logger.info(f"✅ Loaded config from {self.config_path}")
        except FileNotFoundError:
            logger.warning(f"Config file not found: {self.config_path}")
            self.config = self._get_default_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.config = self._get_default_config()
    
    def _load_prompts(self):
        """Load LLM prompts from YAML"""
        prompts_path = "config/prompts.yaml"
        try:
            with open(prompts_path, 'r') as f:
                self.prompts = yaml.safe_load(f)
            logger.info(f"✅ Loaded prompts from {prompts_path}")
        except FileNotFoundError:
            logger.warning(f"Prompts file not found: {prompts_path}")
            self.prompts = {}
        except Exception as e:
            logger.error(f"Error loading prompts: {e}")
            self.prompts = {}
    
    def _override_with_env(self):
        """Override config values with environment variables"""
        # LLM settings
        if os.getenv('GROQ_API_KEY'):
            if 'llm' not in self.config:
                self.config['llm'] = {}
            if 'primary' not in self.config['llm']:
                self.config['llm']['primary'] = {}
        
        if os.getenv('GROQ_MODEL'):
            self.config['llm']['primary']['model'] = os.getenv('GROQ_MODEL')
        
        if os.getenv('OLLAMA_BASE_URL'):
            if 'backup' not in self.config['llm']:
                self.config['llm']['backup'] = {}
            self.config['llm']['backup']['base_url'] = os.getenv('OLLAMA_BASE_URL')
        
        # Database settings
        if os.getenv('CHROMA_DB_PATH'):
            if 'database' not in self.config:
                self.config['database'] = {}
            if 'chromadb' not in self.config['database']:
                self.config['database']['chromadb'] = {}
            self.config['database']['chromadb']['persist_directory'] = os.getenv('CHROMA_DB_PATH')
        
        if os.getenv('SQLITE_DB_PATH'):
            if 'sqlite' not in self.config.get('database', {}):
                self.config['database']['sqlite'] = {}
            self.config['database']['sqlite']['database_path'] = os.getenv('SQLITE_DB_PATH')
        
        # Logging
        if os.getenv('LOG_LEVEL'):
            if 'logging' not in self.config:
                self.config['logging'] = {}
            self.config['logging']['level'] = os.getenv('LOG_LEVEL')
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'project': {
                'name': 'BRAMKA AI',
                'version': '1.0.0'
            },
            'llm': {
                'primary': {
                    'provider': 'groq',
                    'model': 'llama-3.3-70b-versatile',
                    'temperature': 0.7,
                    'max_tokens': 4096
                },
                'backup': {
                    'provider': 'ollama',
                    'model': 'llama3.2:3b',
                    'base_url': 'http://localhost:11434'
                }
            },
            'database': {
                'chromadb': {
                    'persist_directory': './data/vector_db'
                },
                'sqlite': {
                    'database_path': './data/sqlite/bramka.db'
                }
            },
            'logging': {
                'level': 'INFO',
                'files': {
                    'main_log': './data/logs/bramka.log'
                }
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation key
        
        Args:
            key: Dot-notation key (e.g., 'llm.primary.model')
            default: Default value if key not found
        
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_prompt(self, prompt_name: str) -> Optional[str]:
        """
        Get LLM prompt template by name
        
        Args:
            prompt_name: Name of prompt (e.g., 'system_prompt', 'reconnaissance.initial_scan')
        
        Returns:
            Prompt template string or None
        """
        # Handle dot notation for nested prompts
        if '.' in prompt_name:
            keys = prompt_name.split('.')
            value = self.prompts
            
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return None
            
            return value
        
        return self.prompts.get(prompt_name)
    
    def get_all(self) -> Dict[str, Any]:
        """Get complete configuration"""
        return self.config
    
    def reload(self):
        """Reload configuration from files"""
        logger.info("Reloading configuration...")
        self._load_config()
        self._load_prompts()
        self._override_with_env()
        logger.info("✅ Configuration reloaded")

# Global config instance
_config_instance: Optional[ConfigLoader] = None

def get_config(config_path: str = "config/config.yaml") -> ConfigLoader:
    """
    Get global configuration instance (singleton)
    
    Args:
        config_path: Path to config file
    
    Returns:
        ConfigLoader instance
    """
    global _config_instance
    
    if _config_instance is None:
        _config_instance = ConfigLoader(config_path)
    
    return _config_instance
