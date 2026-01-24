"""
BRAMKA AI - Main Agent
The brain that orchestrates all modules and decision-making
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum

from src.core.llm_manager import LLMManager
from src.database.chroma_db import ChromaDBManager
from src.database.sqlite_db import SQLiteManager
from src.utils.logger import setup_logger, get_logger
from src.utils.config_loader import get_config


class AgentState(Enum):
    """Agent operational states"""
    IDLE = "idle"
    LISTENING = "listening"
    THINKING = "thinking"
    EXECUTING = "executing"
    LEARNING = "learning"
    ERROR = "error"


class ConversationContext:
    """Maintains conversation context and memory"""
    
    def __init__(self, max_history: int = 10):
        self.history: List[Dict[str, str]] = []
        self.max_history = max_history
        self.current_task: Optional[str] = None
        self.metadata: Dict[str, Any] = {}
    
    def add_message(self, role: str, content: str, metadata: Optional[Dict] = None):
        """Add message to conversation history"""
        message = {
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        }
        if metadata:
            message["metadata"] = metadata
        
        self.history.append(message)
        
        # Keep only last N messages
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]
    
    def get_history(self) -> List[Dict[str, str]]:
        """Get conversation history for LLM"""
        return [{"role": msg["role"], "content": msg["content"]} 
                for msg in self.history]
    
    def clear(self):
        """Clear conversation history"""
        self.history.clear()
        self.current_task = None
        self.metadata.clear()


class BRAMKAAgent:
    """
    Main BRAMKA AI Agent
    
    Orchestrates all modules:
    - Attack Orchestrator (Module 1)
    - Tool Manager (Module 2)
    - Intelligence Engine (Module 3)
    - Reporting (Module 4)
    """
    
    def __init__(self):
        # Initialize logger
        setup_logger(log_level="INFO", log_file="data/logs/bramka.log")
        self.logger = get_logger("BRAMKAAgent")
        
        self.config = get_config()
        self.state = AgentState.IDLE
        
        # Initialize core components
        self.logger.info("🚀 Initializing BRAMKA AI Agent...")
        
        self.llm = LLMManager()
        self.vector_db = ChromaDBManager()
        self.sql_db = SQLiteManager()
        self.context = ConversationContext(
            max_history=self.config.get("agent.context_window", 10)
        )
        
        # Module placeholders (will be initialized in later phases)
        self.attack_orchestrator = None
        self.tool_manager = None
        self.intelligence_engine = None
        self.reporter = None
        
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.logger.info(f"✅ Agent initialized | Session: {self.session_id}")
    
    async def process_command(self, user_input: str, language: str = "en") -> Dict[str, Any]:
        """
        Process user command through the AI pipeline
        
        Args:
            user_input: User's voice/text command
            language: Language code (en/ta for Tanglish)
        
        Returns:
            Response dictionary with action, message, and metadata
        """
        self.logger.info(f"📥 Command received: {user_input[:100]}...")
        self.state = AgentState.THINKING
        
        try:
            # Add to context
            self.context.add_message("user", user_input)
            
            # Analyze intent using LLM
            intent = await self._analyze_intent(user_input, language)
            self.logger.info(f"🎯 Intent: {intent['category']} - {intent['action']}")
            
            # Route to appropriate module
            response = await self._route_to_module(intent, user_input)
            
            # Add response to context
            self.context.add_message("assistant", response["message"])
            
            # Store interaction for learning
            await self._store_interaction(user_input, response, intent)
            
            self.state = AgentState.IDLE
            return response
            
        except Exception as e:
            self.logger.error(f"❌ Error processing command: {e}", exc_info=True)
            self.state = AgentState.ERROR
            return {
                "success": False,
                "message": f"Error processing your command: {str(e)}",
                "action": "error"
            }
    
    async def _analyze_intent(self, user_input: str, language: str) -> Dict[str, Any]:
        """
        Analyze user intent using LLM
        
        Categories:
        - reconnaissance: Scanning, info gathering
        - exploitation: Attack execution
        - tool_management: Tool discovery/installation
        - reporting: Generate reports
        - conversation: General chat
        """
        prompt = self._build_intent_prompt(user_input, language)
        
        response = await self.llm.generate(
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": user_input}
            ],
            max_tokens=200,
            temperature=0.3  # Low temperature for consistent intent detection
        )
        
        # Parse LLM response into structured intent
        intent_text = response["content"].strip()
        intent = self._parse_intent_response(intent_text)
        
        return intent
    
    def _build_intent_prompt(self, user_input: str, language: str) -> str:
        """Build system prompt for intent analysis"""
        return f"""You are BRAMKA AI's intent analyzer. Analyze the user's command and respond with ONLY a JSON object:

{{
  "category": "reconnaissance|exploitation|tool_management|reporting|conversation",
  "action": "specific action",
  "target": "target if applicable",
  "confidence": 0.0-1.0
}}

Language: {language}
Examples:
- "Scan 192.168.1.1" → {{"category": "reconnaissance", "action": "port_scan", "target": "192.168.1.1", "confidence": 0.95}}
- "zphisher tool download pannu" → {{"category": "tool_management", "action": "install_tool", "target": "zphisher", "confidence": 0.90}}
- "Run SQL injection on example.com" → {{"category": "exploitation", "action": "sql_injection", "target": "example.com", "confidence": 0.92}}

Respond with ONLY the JSON object, no explanation."""
    
    def _parse_intent_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM intent response into structured format"""
        import json
        import re
        
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                intent = json.loads(json_match.group())
            else:
                # Fallback parsing
                intent = {
                    "category": "conversation",
                    "action": "general_chat",
                    "target": None,
                    "confidence": 0.5
                }
            
            # Validate required fields
            required = ["category", "action", "confidence"]
            if not all(k in intent for k in required):
                raise ValueError("Missing required intent fields")
            
            return intent
            
        except Exception as e:
            self.logger.warning(f"⚠️ Intent parsing failed: {e}")
            return {
                "category": "conversation",
                "action": "general_chat",
                "target": None,
                "confidence": 0.3
            }
    
    async def _route_to_module(self, intent: Dict[str, Any], user_input: str) -> Dict[str, Any]:
        """Route command to appropriate module based on intent"""
        category = intent["category"]
        action = intent["action"]
        
        self.logger.info(f"🔀 Routing to module: {category}")
        
        # Route based on category
        if category == "reconnaissance":
            return await self._handle_reconnaissance(intent, user_input)
        
        elif category == "exploitation":
            return await self._handle_exploitation(intent, user_input)
        
        elif category == "tool_management":
            return await self._handle_tool_management(intent, user_input)
        
        elif category == "reporting":
            return await self._handle_reporting(intent, user_input)
        
        else:  # conversation
            return await self._handle_conversation(intent, user_input)
    
    async def _handle_reconnaissance(self, intent: Dict, user_input: str) -> Dict[str, Any]:
        """Handle reconnaissance tasks (Module 1 - placeholder)"""
        self.logger.info("🔍 Reconnaissance module called")
        
        # TODO: Implement in Module 1 phase
        # For now, return acknowledgment
        return {
            "success": True,
            "action": "reconnaissance",
            "message": f"Reconnaissance task acknowledged: {intent['action']}. Module 1 will be implemented in next phase.",
            "data": {
                "intent": intent,
                "status": "pending_module_implementation"
            }
        }
    
    async def _handle_exploitation(self, intent: Dict, user_input: str) -> Dict[str, Any]:
        """Handle exploitation tasks (Module 1 - placeholder)"""
        self.logger.info("⚔️ Exploitation module called")
        
        return {
            "success": True,
            "action": "exploitation",
            "message": f"Exploitation task acknowledged: {intent['action']}. Module 1 will be implemented in next phase.",
            "data": {
                "intent": intent,
                "status": "pending_module_implementation"
            }
        }
    
    async def _handle_tool_management(self, intent: Dict, user_input: str) -> Dict[str, Any]:
        """Handle tool management (Module 2 - placeholder)"""
        self.logger.info("🛠️ Tool management module called")
        
        return {
            "success": True,
            "action": "tool_management",
            "message": f"Tool management task acknowledged: {intent['action']}. Module 2 will be implemented in next phase.",
            "data": {
                "intent": intent,
                "status": "pending_module_implementation"
            }
        }
    
    async def _handle_reporting(self, intent: Dict, user_input: str) -> Dict[str, Any]:
        """Handle reporting tasks (Module 4 - placeholder)"""
        self.logger.info("📊 Reporting module called")
        
        return {
            "success": True,
            "action": "reporting",
            "message": f"Reporting task acknowledged: {intent['action']}. Module 4 will be implemented in next phase.",
            "data": {
                "intent": intent,
                "status": "pending_module_implementation"
            }
        }
    
    async def _handle_conversation(self, intent: Dict, user_input: str) -> Dict[str, Any]:
        """Handle general conversation"""
        self.logger.info("💬 General conversation")
        
        # Use LLM for natural conversation
        response = await self.llm.generate(
            messages=self.context.get_history(),
            max_tokens=500,
            temperature=0.7
        )
        
        return {
            "success": True,
            "action": "conversation",
            "message": response["content"],
            "data": {
                "intent": intent,
                "model_used": response.get("model", "unknown")
            }
        }
    
    async def _store_interaction(self, user_input: str, response: Dict, intent: Dict):
        """Store interaction for learning (Module 3)"""
        try:
            # Store in vector DB for semantic search
            await self.vector_db.add_memory(
                collection_name="interactions",
                text=user_input,
                metadata={
                    "intent": intent["category"],
                    "action": intent["action"],
                    "success": response.get("success", False),
                    "timestamp": datetime.now().isoformat(),
                    "session_id": self.session_id
                }
            )
            
            # Store in SQL for structured queries
            self.sql_db.execute_query(
                """
                INSERT INTO interactions 
                (session_id, user_input, intent_category, intent_action, 
                 response_message, success, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.session_id,
                    user_input,
                    intent["category"],
                    intent["action"],
                    response.get("message", ""),
                    response.get("success", False),
                    datetime.now().isoformat()
                )
            )
            
            self.logger.debug("💾 Interaction stored for learning")
            
        except Exception as e:
            self.logger.warning(f"⚠️ Failed to store interaction: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "state": self.state.value,
            "session_id": self.session_id,
            "context_size": len(self.context.history),
            "current_task": self.context.current_task,
            "modules_loaded": {
                "attack_orchestrator": self.attack_orchestrator is not None,
                "tool_manager": self.tool_manager is not None,
                "intelligence_engine": self.intelligence_engine is not None,
                "reporter": self.reporter is not None
            }
        }
    
    async def shutdown(self):
        """Graceful shutdown"""
        self.logger.info("🛑 Shutting down BRAMKA AI Agent...")
        
        # Close database connections
        self.vector_db.close()
        self.sql_db.close()
        
        self.state = AgentState.IDLE
        self.logger.info("✅ Agent shutdown complete")


# Example usage and testing
async def test_agent():
    """Test the agent with sample commands"""
    agent = BRAMKAAgent()
    
    test_commands = [
        "Hello, are you online?",
        "Scan 192.168.1.1 for open ports",
        "Download and install zphisher tool",
        "Run SQL injection test on example.com"
    ]
    
    for cmd in test_commands:
        print(f"\n{'='*60}")
        print(f"User: {cmd}")
        response = await agent.process_command(cmd)
        print(f"BRAMKA: {response['message']}")
        print(f"Action: {response['action']} | Success: {response.get('success')}")
    
    await agent.shutdown()


if __name__ == "__main__":
    asyncio.run(test_agent())
