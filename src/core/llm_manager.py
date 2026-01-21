"""
BRAMKA AI - LLM Manager
Handles communication with Groq API (primary) and Ollama (backup)
"""

import os
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
import time
from loguru import logger

@dataclass
class LLMResponse:
    """Structured LLM response"""
    content: str
    model: str
    tokens_used: int
    response_time: float
    success: bool
    error: Optional[str] = None
    provider: str = "unknown"

class LLMManager:
    """
    Manages LLM interactions with fallback support.
    Primary: Groq API (fast, free tier)
    Backup: Ollama (local, offline)
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize LLM Manager
        
        Args:
            config: Configuration dictionary with LLM settings
        """
        self.config = config
        self.primary_provider = config.get('llm', {}).get('primary', {})
        self.backup_provider = config.get('llm', {}).get('backup', {})
        self.use_backup_on_failure = config.get('llm', {}).get('settings', {}).get('use_backup_on_failure', True)
        
        # Initialize clients
        self.groq_client = None
        self.ollama_client = None
        
        self._initialize_clients()
        
        logger.info("LLM Manager initialized")
    
    def _initialize_clients(self):
        """Initialize API clients"""
        # Initialize Groq
        try:
            from groq import Groq
            api_key = os.getenv('GROQ_API_KEY')
            
            if api_key and api_key != 'your_groq_api_key_here':
                self.groq_client = Groq(api_key=api_key)
                logger.info("✅ Groq client initialized")
            else:
                logger.warning("⚠️  Groq API key not set")
        except Exception as e:
            logger.error(f"Failed to initialize Groq client: {e}")
        
        # Initialize Ollama (optional)
        try:
            import requests
            ollama_url = self.backup_provider.get('base_url', 'http://localhost:11434')
            
            # Test Ollama connection
            response = requests.get(f"{ollama_url}/api/tags", timeout=2)
            if response.status_code == 200:
                logger.info("✅ Ollama connection available")
            else:
                logger.warning("⚠️  Ollama not responding")
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
    
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        use_primary: bool = True
    ) -> LLMResponse:
        """
        Generate response from LLM
        
        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            temperature: Sampling temperature (optional)
            max_tokens: Maximum tokens in response (optional)
            use_primary: Try primary provider first
        
        Returns:
            LLMResponse object
        """
        start_time = time.time()
        
        # Try primary provider first
        if use_primary and self.groq_client:
            try:
                response = self._generate_groq(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens
                )
                response.response_time = time.time() - start_time
                return response
            except Exception as e:
                logger.warning(f"Groq generation failed: {e}")
                
                # Fallback to Ollama if enabled
                if self.use_backup_on_failure:
                    logger.info("Falling back to Ollama...")
                    return self._generate_ollama(
                        prompt=prompt,
                        system_prompt=system_prompt,
                        temperature=temperature,
                        max_tokens=max_tokens
                    )
                else:
                    return LLMResponse(
                        content="",
                        model="",
                        tokens_used=0,
                        response_time=time.time() - start_time,
                        success=False,
                        error=str(e),
                        provider="groq"
                    )
        
        # Use Ollama directly
        return self._generate_ollama(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens
        )
    
    def _generate_groq(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> LLMResponse:
        """Generate response using Groq API"""
        # Get configuration
        model = self.primary_provider.get('model', 'llama-3.3-70b-versatile')
        temp = temperature or self.primary_provider.get('temperature', 0.7)
        tokens = max_tokens or self.primary_provider.get('max_tokens', 4096)
        
        # Build messages
        messages = []
        
        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt
            })
        
        messages.append({
            "role": "user",
            "content": prompt
        })
        
        # Make API call
        start_time = time.time()
        
        response = self.groq_client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temp,
            max_tokens=tokens,
            top_p=1,
            stream=False
        )
        
        # Parse response
        content = response.choices[0].message.content
        tokens_used = response.usage.total_tokens if hasattr(response, 'usage') else 0
        
        return LLMResponse(
            content=content,
            model=model,
            tokens_used=tokens_used,
            response_time=time.time() - start_time,
            success=True,
            provider="groq"
        )
    
    def _generate_ollama(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> LLMResponse:
        """Generate response using Ollama"""
        try:
            import requests
            
            # Get configuration
            base_url = self.backup_provider.get('base_url', 'http://localhost:11434')
            model = self.backup_provider.get('model', 'llama3.2:3b')
            temp = temperature or self.backup_provider.get('temperature', 0.7)
            
            # Build prompt
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"
            
            # Make API call
            start_time = time.time()
            
            response = requests.post(
                f"{base_url}/api/generate",
                json={
                    "model": model,
                    "prompt": full_prompt,
                    "temperature": temp,
                    "stream": False
                },
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data.get('response', '')
                
                return LLMResponse(
                    content=content,
                    model=model,
                    tokens_used=0,  # Ollama doesn't provide token count easily
                    response_time=time.time() - start_time,
                    success=True,
                    provider="ollama"
                )
            else:
                raise Exception(f"Ollama returned status {response.status_code}")
        
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            return LLMResponse(
                content="",
                model="",
                tokens_used=0,
                response_time=0,
                success=False,
                error=str(e),
                provider="ollama"
            )
    
    def generate_with_context(
        self,
        prompt: str,
        context: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        """
        Generate response with conversation context
        
        Args:
            prompt: Current user prompt
            context: List of previous messages [{"role": "user/assistant", "content": "..."}]
            system_prompt: System prompt
            **kwargs: Additional arguments for generation
        
        Returns:
            LLMResponse object
        """
        # Build full message history
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        # Add context
        messages.extend(context)
        
        # Add current prompt
        messages.append({"role": "user", "content": prompt})
        
        # For now, concatenate for simple generation
        # In production, use proper chat completion endpoint
        full_prompt = "\n\n".join([
            f"{msg['role'].upper()}: {msg['content']}"
            for msg in messages if msg['role'] != 'system'
        ])
        
        return self.generate(
            prompt=full_prompt,
            system_prompt=system_prompt,
            **kwargs
        )
    
    def get_embedding(self, text: str) -> Optional[List[float]]:
        """
        Get text embedding (for semantic search)
        Note: This is a placeholder - you'd use a proper embedding model
        
        Args:
            text: Text to embed
        
        Returns:
            List of floats (embedding vector) or None
        """
        # TODO: Implement proper embedding
        # For now, return None (ChromaDB will use its default)
        return None
    
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
                url = self.backup_provider.get('base_url', 'http://localhost:11434')
                response = requests.get(f"{url}/api/tags", timeout=2)
                return response.status_code == 200
            except:
                return False
        return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about active models"""
        return {
            "primary": {
                "provider": "groq",
                "model": self.primary_provider.get('model'),
                "available": self.is_available("primary")
            },
            "backup": {
                "provider": "ollama",
                "model": self.backup_provider.get('model'),
                "available": self.is_available("backup")
            }
        }
