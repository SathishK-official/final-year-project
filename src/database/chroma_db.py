"""
BRAMKA AI - ChromaDB Manager
Manages vector database for tool knowledge and attack patterns
"""

from typing import List, Dict, Any, Optional
import chromadb
from chromadb.config import Settings

from src.utils.logger import get_logger
from src.utils.config_loader import get_config


class ChromaDBManager:
    """Manages ChromaDB vector database operations"""
    
    def __init__(self):
        """Initialize ChromaDB client"""
        self.logger = get_logger("ChromaDBManager")
        self.config = get_config()
        
        persist_directory = self.config.get("database.chromadb.persist_directory", "./data/vector_db")
        
        # Initialize persistent client
        self.client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Collections
        self.tool_knowledge = None
        self.attack_patterns = None
        self.exploit_db = None
        self.interactions = None
        
        self._initialize_collections()
        
        self.logger.info(f"✅ ChromaDB initialized at {persist_directory}")
    
    def _initialize_collections(self):
        """Initialize or get existing collections"""
        try:
            # Tool knowledge collection
            self.tool_knowledge = self.client.get_or_create_collection(
                name="tool_knowledge",
                metadata={"description": "Tool usage patterns and knowledge"}
            )
            
            # Attack patterns collection
            self.attack_patterns = self.client.get_or_create_collection(
                name="attack_patterns",
                metadata={"description": "Successful attack patterns"}
            )
            
            # Exploit database collection
            self.exploit_db = self.client.get_or_create_collection(
                name="exploit_database",
                metadata={"description": "Known exploits and CVEs"}
            )
            
            # Interactions collection (for agent memory)
            self.interactions = self.client.get_or_create_collection(
                name="interactions",
                metadata={"description": "User interactions and conversations"}
            )
            
            self.logger.info("✅ ChromaDB collections initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing collections: {e}")
    
    async def add_memory(
        self,
        collection_name: str,
        text: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Add memory to a collection (for agent interactions)
        
        Args:
            collection_name: Name of collection
            text: Text to store
            metadata: Metadata dictionary
        
        Returns:
            Success boolean
        """
        try:
            # Get collection
            if collection_name == "interactions":
                collection = self.interactions
            elif collection_name == "tool_knowledge":
                collection = self.tool_knowledge
            elif collection_name == "attack_patterns":
                collection = self.attack_patterns
            else:
                self.logger.warning(f"Unknown collection: {collection_name}")
                return False
            
            # Generate ID
            from datetime import datetime
            memory_id = f"{collection_name}_{datetime.now().timestamp()}"
            
            # Add to collection
            collection.add(
                documents=[text],
                metadatas=[metadata] if metadata else [{}],
                ids=[memory_id]
            )
            
            self.logger.debug(f"💾 Added memory to {collection_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding memory: {e}")
            return False
    
    def store_tool_knowledge(
        self,
        tool_name: str,
        knowledge: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Store tool usage knowledge
        
        Args:
            tool_name: Name of the tool
            knowledge: Knowledge dictionary (usage patterns, commands, etc.)
            metadata: Additional metadata
        
        Returns:
            Success boolean
        """
        try:
            # Prepare document
            document = f"""
            Tool: {tool_name}
            Purpose: {knowledge.get('purpose', 'Unknown')}
            Category: {knowledge.get('category', 'Unknown')}
            Command Syntax: {knowledge.get('command_syntax', 'Unknown')}
            Usage Examples: {', '.join(knowledge.get('usage_examples', []))}
            Tips: {', '.join(knowledge.get('learned_tips', []))}
            """
            
            # Prepare metadata
            meta = metadata or {}
            meta.update({
                'tool_name': tool_name,
                'category': knowledge.get('category', 'unknown'),
                'success_rate': knowledge.get('success_rate', 0.0)
            })
            
            # Store in collection
            self.tool_knowledge.add(
                documents=[document],
                metadatas=[meta],
                ids=[f"tool_{tool_name}"]
            )
            
            self.logger.info(f"✅ Stored knowledge for tool: {tool_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error storing tool knowledge: {e}")
            return False
    
    def get_tool_knowledge(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve tool knowledge
        
        Args:
            tool_name: Name of the tool
        
        Returns:
            Tool knowledge dictionary or None
        """
        try:
            result = self.tool_knowledge.get(ids=[f"tool_{tool_name}"])
            
            if result['documents']:
                return {
                    'document': result['documents'][0],
                    'metadata': result['metadatas'][0] if result['metadatas'] else {}
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error retrieving tool knowledge: {e}")
            return None
    
    def search_similar_tools(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """
        Search for similar tools based on query
        
        Args:
            query: Search query
            n_results: Number of results to return
        
        Returns:
            List of similar tools with metadata
        """
        try:
            results = self.tool_knowledge.query(
                query_texts=[query],
                n_results=n_results
            )
            
            tools = []
            if results['documents']:
                for i, doc in enumerate(results['documents'][0]):
                    tools.append({
                        'document': doc,
                        'metadata': results['metadatas'][0][i] if results['metadatas'] else {},
                        'distance': results['distances'][0][i] if results['distances'] else None
                    })
            
            return tools
            
        except Exception as e:
            self.logger.error(f"Error searching tools: {e}")
            return []
    
    def store_attack_pattern(
        self,
        attack_id: str,
        pattern: Dict[str, Any]
    ) -> bool:
        """
        Store successful attack pattern for learning
        
        Args:
            attack_id: Unique attack identifier
            pattern: Attack pattern details
        
        Returns:
            Success boolean
        """
        try:
            document = f"""
            Attack Type: {pattern.get('attack_type', 'Unknown')}
            Target Type: {pattern.get('target_type', 'Unknown')}
            Tools Used: {', '.join(pattern.get('tools_used', []))}
            Success: {pattern.get('success', False)}
            Method: {pattern.get('method', 'Unknown')}
            """
            
            metadata = {
                'attack_type': pattern.get('attack_type'),
                'target_type': pattern.get('target_type'),
                'success': pattern.get('success', False),
                'timestamp': pattern.get('timestamp', '')
            }
            
            self.attack_patterns.add(
                documents=[document],
                metadatas=[metadata],
                ids=[f"attack_{attack_id}"]
            )
            
            self.logger.info(f"✅ Stored attack pattern: {attack_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error storing attack pattern: {e}")
            return False
    
    def get_successful_patterns(
        self,
        target_type: Optional[str] = None,
        attack_type: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Retrieve successful attack patterns
        
        Args:
            target_type: Filter by target type (optional)
            attack_type: Filter by attack type (optional)
            limit: Maximum results
        
        Returns:
            List of successful patterns
        """
        try:
            # Build where clause
            where = {"success": True}
            if target_type:
                where['target_type'] = target_type
            if attack_type:
                where['attack_type'] = attack_type
            
            results = self.attack_patterns.get(
                where=where,
                limit=limit
            )
            
            patterns = []
            if results['documents']:
                for i, doc in enumerate(results['documents']):
                    patterns.append({
                        'document': doc,
                        'metadata': results['metadatas'][i] if results['metadatas'] else {}
                    })
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Error retrieving patterns: {e}")
            return []
    
    def get_collection_stats(self) -> Dict[str, int]:
        """Get statistics about collections"""
        try:
            return {
                'tool_knowledge_count': self.tool_knowledge.count(),
                'attack_patterns_count': self.attack_patterns.count(),
                'exploits_count': self.exploit_db.count(),
                'interactions_count': self.interactions.count()
            }
        except Exception as e:
            self.logger.error(f"Error getting stats: {e}")
            return {}
    
    def close(self):
        """Close ChromaDB connection"""
        self.logger.info("🔒 ChromaDB connection closed")
