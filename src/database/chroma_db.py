"""
BRAMKA AI - ChromaDB Manager
Manages vector database for tool knowledge and attack patterns
"""

from typing import List, Dict, Any, Optional
import chromadb
from chromadb.config import Settings
from loguru import logger

class ChromaDBManager:
    """Manages ChromaDB vector database operations"""
    
    def __init__(self, persist_directory: str = "./data/vector_db"):
        """
        Initialize ChromaDB client
        
        Args:
            persist_directory: Directory to persist vector database
        """
        self.persist_directory = persist_directory
        
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
        
        self._initialize_collections()
        
        logger.info(f"ChromaDB initialized at {persist_directory}")
    
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
            
            logger.info("✅ ChromaDB collections initialized")
            
        except Exception as e:
            logger.error(f"Error initializing collections: {e}")
    
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
            
            logger.info(f"✅ Stored knowledge for tool: {tool_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing tool knowledge: {e}")
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
            logger.error(f"Error retrieving tool knowledge: {e}")
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
            logger.error(f"Error searching tools: {e}")
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
            
            logger.info(f"✅ Stored attack pattern: {attack_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing attack pattern: {e}")
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
            logger.error(f"Error retrieving patterns: {e}")
            return []
    
    def store_exploit(
        self,
        cve_id: str,
        exploit_info: Dict[str, Any]
    ) -> bool:
        """
        Store exploit information
        
        Args:
            cve_id: CVE identifier
            exploit_info: Exploit details
        
        Returns:
            Success boolean
        """
        try:
            document = f"""
            CVE: {cve_id}
            Title: {exploit_info.get('title', 'Unknown')}
            Description: {exploit_info.get('description', 'Unknown')}
            Affected Systems: {exploit_info.get('affected_systems', 'Unknown')}
            Severity: {exploit_info.get('severity', 'Unknown')}
            """
            
            metadata = {
                'cve_id': cve_id,
                'severity': exploit_info.get('severity', 'unknown'),
                'type': exploit_info.get('type', 'unknown')
            }
            
            self.exploit_db.add(
                documents=[document],
                metadatas=[metadata],
                ids=[f"cve_{cve_id}"]
            )
            
            logger.info(f"✅ Stored exploit: {cve_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing exploit: {e}")
            return False
    
    def search_exploits(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """
        Search for relevant exploits
        
        Args:
            query: Search query (service name, version, etc.)
            n_results: Number of results
        
        Returns:
            List of relevant exploits
        """
        try:
            results = self.exploit_db.query(
                query_texts=[query],
                n_results=n_results
            )
            
            exploits = []
            if results['documents']:
                for i, doc in enumerate(results['documents'][0]):
                    exploits.append({
                        'document': doc,
                        'metadata': results['metadatas'][0][i] if results['metadatas'] else {},
                        'relevance': 1 - results['distances'][0][i] if results['distances'] else 0
                    })
            
            return exploits
            
        except Exception as e:
            logger.error(f"Error searching exploits: {e}")
            return []
    
    def get_collection_stats(self) -> Dict[str, int]:
        """Get statistics about collections"""
        try:
            return {
                'tool_knowledge_count': self.tool_knowledge.count(),
                'attack_patterns_count': self.attack_patterns.count(),
                'exploits_count': self.exploit_db.count()
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {}
    
    def reset_collection(self, collection_name: str) -> bool:
        """
        Reset (clear) a collection
        
        Args:
            collection_name: Name of collection to reset
        
        Returns:
            Success boolean
        """
        try:
            self.client.delete_collection(collection_name)
            self._initialize_collections()
            logger.warning(f"⚠️  Collection reset: {collection_name}")
            return True
        except Exception as e:
            logger.error(f"Error resetting collection: {e}")
            return False
