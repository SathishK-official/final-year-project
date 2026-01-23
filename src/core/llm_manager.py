"""
BRAMKA AI - LLM Manager
Handles communication with Groq API (primary) and Ollama (backup)
"""

import os
from typing import Optional, Dict, List, Any
import asyncio
import time

from src.utils.logger import get_logger
from src.utils.config_loader import get_config


class LLMManager:
    """
    Manages LLM interactions with fallback support.
    Primary: Groq API (fast, free tier)
    Backup: Ollama (local, offline)
    """
    
    def __init__(self):
        """Initialize LLM Manager"""
        self.logger = get_logger("LLMManager")
        self.config = get_config()
        
        # Get LLM configuration
        self.primary_config = self.config.get('llm.primary', {})
        self.backup_config = self.config.get('llm.backup', {})
        self.use_backup_on_failure = self.config.get('llm.settings.use_backup_on_failure', True)
        
        # Initialize clients
        self.groq_client = None
        self.ollama_base_url = None
        
        self._initialize_clients()
        
        self.logger.info("✅ LLM Manager initialized")
    
    def _initialize_clients(self):
        """Initialize API clients"""
        # Initialize Groq
        try:
            from groq import Groq
            api_key = os.getenv('GROQ_API_KEY')
            
            if api_key and api_key != 'your_groq_api_key_here':
                self.groq_client = Groq(api_key=api_key)
                self.logger.info("✅ Groq client initialized")
            else:
                self.logger.warning("⚠️ Groq API key not set")
        except Exception as e:
            self.logger.error(f"Failed to initialize Groq client: {e}")
        
        # Initialize Ollama URL
        try:
            import requests
            self.ollama_base_url = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
            
            # Test Ollama connection
            response = requests.get(f"{self.ollama_base_url}/api/tags", timeout=2)
            if response.status_code == 200:
                self.logger.info("✅ Ollama connection available")
            else:
                self.logger.warning("⚠️ Ollama not responding")
        except Exception as e:
            self.logger.debug(f"Ollama not available: {e}")
    
    async def generate(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        use_primary: bool = True
    ) -> Dict[str, Any]:
        """
        Generate response from LLM
        
        Args:
            messages: List of message dicts [{"role": "user/system/assistant", "content": "..."}]
            temperature: Sampling temperature (optional)
            max_tokens: Maximum tokens in response (optional)
            use_primary: Try primary provider first
        
        Returns:
            Response dictionary with 'content', 'model', 'tokens_used', etc.
        """
        start_time = time.time()
        
        # Try primary provider first
        if use_primary and self.groq_client:
            try:
                response = await self._generate_groq(
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens
                )
                response['response_time'] = time.time() - start_time
                return response
            except Exception as e:
                self.logger.warning(f"Groq generation failed: {e}")
                
                # Fallback to Ollama if enabled
                if self.use_backup_on_failure:
                    self.logger.info("Falling back to Ollama...")
                    return await self._generate_ollama(
                        messages=messages,
                        temperature=temperature,
                        max_tokens=max_tokens
                    )
                else:
                    return {
                        "content": "",
                        "model": "",
                        "tokens_used": 0,
                        "response_time": time.time() - start_time,
                        "success": False,
                        "error": str(e),
                        "provider": "groq"
                    }
        
        # Use Ollama directly
        return await self._generate_ollama(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens
        )
    
    async def _generate_groq(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> Dict[str, Any]:
        """Generate response using Groq API"""
        # Get configuration
        model = self.primary_config.get('model', 'llama-3.3-70b-versatile')
        temp = temperature if temperature is not None else self.primary_config.get('temperature', 0.7)
        tokens = max_tokens if max_tokens is not None else self.primary_config.get('max_tokens', 4096)
        
        # Make API call (run in thread pool since Groq client is sync)
        loop = asyncio.get_event_loop()
        
        def _call_groq():
            return self.groq_client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temp,
                max_tokens=tokens,
                top_p=1,
                stream=False
            )
        
        response = await loop.run_in_executor(None, _call_groq)
        
        # Parse response
        content = response.choices[0].message.content
        tokens_used = response.usage.total_tokens if hasattr(response, 'usage') else 0
        
        return {
            "content": content,
            "model": model,
            "tokens_used": tokens_used,
            "success": True,
            "provider": "groq"
        }
    
    async def _generate_ollama(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> Dict[str, Any]:
        """Generate response using Ollama"""
        try:
            import aiohttp
            
            # Get configuration
            model = self.backup_config.get('model', 'llama3.2:3b')
            temp = temperature if temperature is not None else self.backup_config.get('temperature', 0.7)
            
            # Convert messages to single prompt for Ollama
            system_prompt = ""
            user_messages = []
            
            for msg in messages:
                if msg['role'] == 'system':
                    system_prompt = msg['content']
                else:
                    user_messages.append(f"{msg['role'].upper()}: {msg['content']}")
            
            full_prompt = f"{system_prompt}\n\n" + "\n\n".join(user_messages) if system_prompt else "\n\n".join(user_messages)
            
            # Make API call
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.ollama_base_url}/api/generate",
                    json={
                        "model": model,
                        "prompt": full_prompt,
                        "temperature": temp,
                        "stream": False
                    },
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    
                    if response.status == 200:
                        data = await response.json()
                        content = data.get('response', '')
                        
                        return {
                            "content": content,
                            "model": model,
                            "tokens_used": 0,  # Ollama doesn't provide token count easily
                            "success": True,
                            "provider": "ollama"
                        }
                    else:
                        raise Exception(f"Ollama returned status {response.status}")
        
        except Exception as e:
            self.logger.error(f"Ollama generation failed: {e}")
            return {
                "content": "",
                "model": "",
                "tokens_used": 0,
                "success": False,
                "error": str(e),
                "provider": "ollama"
            }
    
    def is_available(self, provider: str = "primary") -> bool:
        """
        Check if LLM provider is available
        
        Args:
            provider: "primary" or "backup"
        
        Returns:
            Boolean indicating availability
        """
        if provider == "primary":
            return self.groq_client is not None
        elif provider == "backup":
            try:
                import requests
                response = requests.get(f"{self.ollama_base_url}/api/tags", timeout=2)
                return response.status_code == 200
            except:
                return False
        return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about active models"""
        return {
            "primary": {
                "provider": "groq",
                "model": self.primary_config.get('model'),
                "available": self.is_available("primary")
            },
            "backup": {
                "provider": "ollama",
                "model": self.backup_config.get('model'),
                "available": self.is_available("backup")
            }
        }
