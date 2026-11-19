import boto3
import json
import numpy as np
from typing import List, Dict, Any, Optional
from core import Config, logger

class AWSBedrockService:
    """Service for AWS Bedrock Titan text embedding model."""
    
    def __init__(self):
        """Initialize AWS Bedrock client and configure Titan embedding model."""
        try:
            # Initialize Bedrock client
            self.client = boto3.client(
                'bedrock-runtime',
                region_name=Config.AWS_REGION,
                aws_access_key_id=Config.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=Config.AWS_SECRET_ACCESS_KEY
            )
            
            # Titan Text Embeddings V2 model ID
            self.model_id = "amazon.titan-embed-text-v2:0"
            self.embedding_dimension = 1024  # Titan V2 embedding dimension
            
            # Titan Text Express model for conversational responses
            self.text_model_id = "amazon.titan-text-lite-v1"
            
            logger.info("AWS Bedrock service initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing AWS Bedrock service: {str(e)}")
            raise
    
    def get_embeddings(self, texts: List[str], input_type: str = "search_document") -> List[List[float]]:
        """
        Get embeddings for a list of texts using AWS Titan model.
        
        Args:
            texts (List[str]): List of texts to embed
            input_type (str): Type of input ("search_document" or "search_query")
            
        Returns:
            List[List[float]]: List of embedding vectors
        """
        try:
            embeddings = []
            
            for text in texts:
                # Prepare the request body for Titan V2
                body = {
                    "inputText": text,
                    "dimensions": self.embedding_dimension,
                    "normalize": True,
                    "embeddingTypes": ["float"]
                }
                
                # If input type is specified, add it to the request
                if input_type:
                    body["inputType"] = input_type
                
                # Invoke the model
                response = self.client.invoke_model(
                    body=json.dumps(body),
                    modelId=self.model_id,
                    accept="application/json",
                    contentType="application/json"
                )
                
                # Parse the response
                response_body = json.loads(response.get('body').read())
                embedding = response_body.get('embedding', [])
                
                if embedding:
                    embeddings.append(embedding)
                else:
                    logger.warning(f"No embedding returned for text: {text[:50]}...")
                    # Add zero vector as fallback
                    embeddings.append([0.0] * self.embedding_dimension)
            
            logger.info(f"Generated embeddings for {len(texts)} texts")
            return embeddings
            
        except Exception as e:
            logger.error(f"Error generating embeddings: {str(e)}")
            # Return zero vectors as fallback
            return [[0.0] * self.embedding_dimension for _ in texts]
    
    def get_single_embedding(self, text: str, input_type: str = "search_query") -> List[float]:
        """
        Get embedding for a single text.
        
        Args:
            text (str): Text to embed
            input_type (str): Type of input ("search_document" or "search_query")
            
        Returns:
            List[float]: Embedding vector
        """
        embeddings = self.get_embeddings([text], input_type)
        return embeddings[0] if embeddings else [0.0] * self.embedding_dimension
    
    async def search_mitre_techniques(self, query: str, chromadb_service, n_results: int = 5) -> List[Dict[str, Any]]:
        """
        Search MITRE techniques using AWS Titan embeddings for better context retrieval.
        
        Args:
            query (str): Search query
            chromadb_service: ChromaDB service instance
            n_results (int): Number of results to return
            
        Returns:
            List[Dict]: Enhanced search results with better context
        """
        try:
            # Get query embedding using Titan
            query_embedding = self.get_single_embedding(query, "search_query")
            
            # Perform similarity search in ChromaDB using the embedding
            results = chromadb_service.collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results
            )
            
            techniques = []
            if results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    metadata = results['metadatas'][0][i]
                    distance = results['distances'][0][i] if 'distances' in results else None
                    
                    # Calculate relevance score (higher is better)
                    if distance is not None:
                        # Convert distance to similarity score (0-1 scale)
                        relevance_score = max(0, 1 - distance)
                    else:
                        relevance_score = 0.0
                    
                    technique = {
                        'technique_id': metadata.get('technique_id', ''),
                        'name': metadata.get('name', ''),
                        'description': metadata.get('description', ''),
                        'kill_chain_phases': metadata.get('kill_chain_phases', '').split(',') if metadata.get('kill_chain_phases') else [],
                        'platforms': metadata.get('platforms', '').split(',') if metadata.get('platforms') else [],
                        'relevance_score': relevance_score,
                        'embedding_model': 'aws-titan-v2',
                        'document': doc
                    }
                    techniques.append(technique)
            
            # Sort by relevance score (highest first)
            techniques.sort(key=lambda x: x['relevance_score'], reverse=True)
            
            logger.info(f"Found {len(techniques)} techniques using AWS Titan embeddings")
            return techniques
            
        except Exception as e:
            logger.error(f"Error searching MITRE techniques with AWS Titan: {str(e)}")
            return []
    
    async def generate_mitre_response(self, query: str, context_techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a comprehensive response about MITRE framework data.
        
        Args:
            query (str): User query
            context_techniques (List[Dict]): Relevant MITRE techniques from context
            
        Returns:
            Dict: Structured response with techniques and insights
        """
        try:
            # Prepare context from techniques
            context_text = ""
            for technique in context_techniques[:3]:  # Use top 3 most relevant
                context_text += f"""
            Technique: {technique['name']} ({technique['technique_id']})
            Description: {technique['description']}
            Tactics: {', '.join(technique['kill_chain_phases'])}
            Platforms: {', '.join(technique['platforms'])}
            Relevance Score: {technique['relevance_score']:.3f}

"""
            
            response = {
                "query": query,
                "relevant_techniques": context_techniques,
                "summary": f"Found {len(context_techniques)} relevant MITRE ATT&CK techniques",
                "context": context_text.strip(),
                "embedding_model": "aws-titan-v2",
                "total_techniques": len(context_techniques)
            }
            
            # Add insights based on the techniques found
            if context_techniques:
                top_technique = context_techniques[0]
                response["top_match"] = {
                    "technique_id": top_technique['technique_id'],
                    "name": top_technique['name'],
                    "relevance_score": top_technique['relevance_score'],
                    "description": top_technique['description'][:200] + "..." if len(top_technique['description']) > 200 else top_technique['description']
                }
                
                # Extract common tactics
                all_tactics = []
                for tech in context_techniques:
                    all_tactics.extend(tech['kill_chain_phases'])
                
                unique_tactics = list(set([tactic for tactic in all_tactics if tactic]))
                response["common_tactics"] = unique_tactics[:5]  # Top 5 tactics
                
                # Extract common platforms
                all_platforms = []
                for tech in context_techniques:
                    all_platforms.extend(tech['platforms'])
                
                unique_platforms = list(set([platform for platform in all_platforms if platform]))
                response["common_platforms"] = unique_platforms[:5]  # Top 5 platforms
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating MITRE response: {str(e)}")
            return {
                "query": query,
                "error": str(e),
                "relevant_techniques": [],
                "summary": "Error processing query"
            }
    
    async def generate_conversational_response(self, query: str, context: str, max_tokens: int = 500, structured: bool = False) -> str:
        """
        Generate a conversational response using AWS Titan Text Express.

        Args:
            query (str): User's query
            context (str): Context from relevant MITRE techniques
            max_tokens (int): Maximum tokens in response
            structured (bool): If True, ask the model to return a single JSON object

        Returns:
            str: Generated conversational response (plain text or JSON string when structured=True)
        """
        try:
            if structured:
                # Strict prompt asking for a single JSON object. Provide schema and a short example.
                prompt = f"""
You are an expert cybersecurity analyst specialized in MITRE ATT&CK. Based on the context below, return exactly one valid JSON object (no surrounding commentary) that follows the schema described.

Schema (fields and types):
- summary: string (1-2 short sentences)
- priority: string (one of "low", "medium", "high") — recommended action priority
- detection_strategies: array of strings (concise, actionable detection ideas)
- mitigation_recommendations: array of strings (concise, actionable mitigations)
- related_techniques: array of objects with {"technique_id": string, "name": string, "relevance_score": number}
- references: array of strings (URLs or short citations)
- notes: string (optional short note or caveat)

Rules:
- Return ONLY one JSON object. Do not include any explanatory text before or after.
- Use short arrays (max 3 items per array). Use empty arrays or empty strings if information is missing.
- Keep values concise and actionable.
- If a field is not applicable, use an empty string or empty array.

Context:
{context}

User Query: {query}

Example output:
{{
  "summary": "Elevated process execution observed that matches techniques for credential dumping.",
  "priority": "high",
  "detection_strategies": ["Monitor for unusual PowerShell parent-child processes", "Alert on lsass memory read attempts"],
  "mitigation_recommendations": ["Harden LSASS access", "Apply least privilege for admin accounts"],
  "related_techniques": [{"technique_id": "T1003", "name": "Credential Dumping", "relevance_score": 0.92}],
  "references": ["https://attack.mitre.org/techniques/T1003/"],
  "notes": "Focus on endpoint monitoring and credential hygiene."
}}

Provide only the JSON object.
""".strip()
            else:
                prompt = f"""
You are an expert cybersecurity analyst specializing in the MITRE ATT&CK framework. 
You help users understand attack techniques, tactics, and procedures to improve their security posture.

Based on the following context from relevant MITRE ATT&CK techniques, provide a helpful and conversational response to the user's query.

{context}

Guidelines for your response:
- Be conversational and helpful, like a knowledgeable colleague
- Focus on practical cybersecurity insights and actionable advice
- Explain technical concepts in clear, understandable terms
- Suggest detection strategies and mitigation approaches when relevant
- Keep the response concise but informative (aim for 2-3 paragraphs)
- Use natural language, not just listing techniques
- If the query is about a specific technique, provide context about how it fits into the broader attack lifecycle

User Query: {query}

Response:"""
            
            logger.info(f"Generating response for query: {query[:50]}...")
            
            # Prepare the request body for Titan Text Lite
            body = {
                "inputText": prompt,
                "textGenerationConfig": {
                    "maxTokenCount": max_tokens,
                    "temperature": 0.7,
                    "topP": 0.9
                }
            }
            
            logger.info(f"Invoking Titan model: {self.text_model_id}")
            
            # Invoke the Titan Text model
            response = self.client.invoke_model(
                body=json.dumps(body),
                modelId=self.text_model_id,
                accept="application/json",
                contentType="application/json"
            )
            
            # Parse the response
            response_body = json.loads(response.get('body').read())
            generated_text = response_body.get('results', [{}])[0].get('outputText', '')
            
            logger.info(f"Titan response received, length: {len(generated_text) if generated_text else 0}")
            
            if generated_text:
                # Clean up the response
                cleaned_response = generated_text.strip()
                # Remove any prompt leakage for the non-structured mode
                if not structured and "Response:" in cleaned_response:
                    cleaned_response = cleaned_response.split("Response:", 1)[1].strip()

                # If structured output was requested, try to extract JSON and validate it
                if structured:
                    try:
                        # Attempt to find the first JSON object in the output
                        first_brace = cleaned_response.find('{')
                        last_brace = cleaned_response.rfind('}')
                        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                            json_text = cleaned_response[first_brace:last_brace+1]
                        else:
                            json_text = cleaned_response

                        parsed = json.loads(json_text)
                        # Return pretty-printed JSON string for callers that expect text
                        logger.info("Generated structured JSON response using Titan Text Lite")
                        return json.dumps(parsed, indent=2)
                    except Exception as e:
                        logger.warning(f"Failed to parse structured JSON from model output: {e}; returning raw text")
                        logger.debug(f"Raw model output: {cleaned_response}")
                        return cleaned_response

                logger.info(f"Generated conversational response using Titan Text Lite")
                return cleaned_response
            else:
                logger.warning("No text generated by Titan Text Lite")
                return self._generate_fallback_response(query)
                
        except Exception as e:
            logger.error(f"Error generating conversational response with Titan: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            return self._generate_fallback_response(query)
    
    def _generate_fallback_response(self, query: str) -> str:
        """Generate a fallback response when Titan text generation fails."""
        return f"I understand you're asking about '{query}' in the context of cybersecurity and MITRE ATT&CK. While I'm currently unable to generate a detailed response, I can tell you that the MITRE ATT&CK framework is an excellent resource for understanding adversary behaviors. I recommend exploring the official MITRE ATT&CK website or using the search functionality in our analysis tools to get specific information about techniques, tactics, and procedures relevant to your query."
