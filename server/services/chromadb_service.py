import json
import os
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any
from core import Config, logger

# Disable ChromaDB telemetry to reduce noise
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")

class AttackDataProcessor:
    """Process MITRE ATT&CK STIX data for ChromaDB storage."""
    
    def __init__(self):
        self.data_path = Config.ATTACK_DATA_PATH
        logger.info("Attack data processor initialized")
    
    def load_attack_data(self) -> List[Dict[str, Any]]:
        """Load and process MITRE ATT&CK data from STIX JSON."""
        try:
            with open(self.data_path, 'r', encoding='utf-8') as f:
                stix_data = json.load(f)
            
            techniques = []
            
            for obj in stix_data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    technique = {
                        'id': obj.get('id', ''),
                        'technique_id': obj.get('external_references', [{}])[0].get('external_id', ''),
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'kill_chain_phases': [phase.get('phase_name', '') for phase in obj.get('kill_chain_phases', [])],
                        'platforms': obj.get('x_mitre_platforms', []),
                        'tactics': obj.get('kill_chain_phases', []),
                        'modified': obj.get('modified', ''),
                        'created': obj.get('created', '')
                    }
                    
                    # Create searchable text combining multiple fields
                    searchable_text = f"{technique['name']} {technique['description']} {' '.join(technique['kill_chain_phases'])} {' '.join(technique['platforms'])}"
                    technique['searchable_text'] = searchable_text
                    
                    techniques.append(technique)
            
            logger.info(f"Loaded {len(techniques)} attack techniques")
            return techniques
            
        except Exception as e:
            logger.error(f"Error loading attack data: {str(e)}")
            return []

class ChromaDBService:
    """Service for managing ChromaDB vector database with MITRE ATT&CK data."""
    
    def __init__(self):
        try:
            # Initialize ChromaDB client
            self.client = chromadb.PersistentClient(
                path=Config.CHROMA_PERSIST_DIRECTORY,
                settings=Settings(anonymized_telemetry=False)
            )
            
            # Try to initialize embedding model, fallback to default if offline
            self.embedding_model = None
            try:
                self.embedding_model = SentenceTransformer(Config.EMBEDDING_MODEL)
                logger.info("Embedding model loaded successfully")
                
                # Get or create collection with sentence transformer embeddings
                self.collection = self.client.get_or_create_collection(
                    name="mitre_attack_techniques",
                    metadata={"description": "MITRE ATT&CK Enterprise techniques for RAG"}
                )
                
            except Exception as e:
                logger.warning(f"Failed to load embedding model: {str(e)}")
                logger.warning("Running in offline mode with default embeddings")
                
                # Get or create collection with default embeddings (no external dependencies)
                self.collection = self.client.get_or_create_collection(
                    name="mitre_attack_techniques_default",
                    metadata={"description": "MITRE ATT&CK Enterprise techniques for RAG (default embeddings)"}
                )
            
            self.attack_processor = AttackDataProcessor()
            logger.info("ChromaDB service initialized")
            
        except Exception as e:
            logger.error(f"Error initializing ChromaDB service: {str(e)}")
            raise
    
    async def initialize_database(self) -> bool:
        """Initialize the database with MITRE ATT&CK data if not already done."""
        try:
            # Check if collection is already populated
            count = self.collection.count()
            if count > 0:
                logger.info(f"Database already contains {count} techniques")
                return True
            
            # Load and process attack data
            techniques = self.attack_processor.load_attack_data()
            if not techniques:
                logger.warning("No techniques loaded from attack data - running without MITRE data")
                logger.warning("Some analysis features may be limited")
                return True  # Allow server to start without MITRE data
            
            # Prepare data for ChromaDB
            documents = []
            metadatas = []
            ids = []
            
            for technique in techniques:
                documents.append(technique['searchable_text'])
                metadatas.append({
                    'technique_id': technique['technique_id'],
                    'name': technique['name'],
                    'description': technique['description'][:1000],  # Limit description length
                    'kill_chain_phases': ','.join(technique['kill_chain_phases']),
                    'platforms': ','.join(technique['platforms'])
                })
                ids.append(technique['id'])
            
            # Add to ChromaDB in batches
            batch_size = 100
            for i in range(0, len(documents), batch_size):
                batch_docs = documents[i:i+batch_size]
                batch_metas = metadatas[i:i+batch_size]
                batch_ids = ids[i:i+batch_size]
                
                self.collection.add(
                    documents=batch_docs,
                    metadatas=batch_metas,
                    ids=batch_ids
                )
                
                logger.info(f"Added batch {i//batch_size + 1}/{(len(documents) + batch_size - 1)//batch_size}")
            
            logger.info(f"Successfully initialized database with {len(techniques)} techniques")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            return True  # Allow server to start even if database init fails
    
    async def search_techniques(self, query: str, n_results: int = None) -> List[Dict[str, Any]]:
        """
        Search for relevant MITRE ATT&CK techniques based on query.
        
        Args:
            query (str): Search query (typically log summary)
            n_results (int): Number of results to return
            
        Returns:
            List[Dict]: List of matching techniques with metadata
        """
        try:
            if n_results is None:
                n_results = Config.MAX_RESULTS
            
            # Perform semantic search
            results = self.collection.query(
                query_texts=[query],
                n_results=min(n_results, 20)  # Limit to prevent excessive results
            )
            
            techniques = []
            if results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    metadata = results['metadatas'][0][i]
                    distance = results['distances'][0][i] if 'distances' in results else None
                    
                    # Normalize distance to relevance score
                    # For cosine distance: 0 = identical, 2 = completely opposite
                    # Convert to 0-1 scale where 1 = most relevant, 0 = least relevant
                    if distance is not None:
                        # Clamp distance to reasonable range and normalize
                        clamped_distance = max(0, min(distance, 2.0))
                        relevance_score = 1.0 - (clamped_distance / 2.0)
                    else:
                        relevance_score = 0.0
                    
                    technique = {
                        'technique_id': metadata.get('technique_id', ''),
                        'name': metadata.get('name', ''),
                        'description': metadata.get('description', ''),
                        'kill_chain_phases': metadata.get('kill_chain_phases', '').split(',') if metadata.get('kill_chain_phases') else [],
                        'platforms': metadata.get('platforms', '').split(',') if metadata.get('platforms') else [],
                        'relevance_score': relevance_score,
                        'document': doc
                    }
                    techniques.append(technique)
            
            logger.info(f"Found {len(techniques)} matching techniques for query")
            return techniques
            
        except Exception as e:
            logger.error(f"Error searching techniques: {str(e)}")
            return []
    
    async def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the ChromaDB collection."""
        try:
            count = self.collection.count()
            return {
                'total_techniques': count,
                'collection_name': self.collection.name,
                'embedding_model': Config.EMBEDDING_MODEL
            }
        except Exception as e:
            logger.error(f"Error getting collection stats: {str(e)}")
            return {'error': str(e)}
