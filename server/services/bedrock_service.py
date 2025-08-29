import boto3
import json
import os
import re
from typing import Optional, List, Dict, Any
from core.config import settings

class BedrockService:
    """Service for interacting with AWS Bedrock for log analysis."""
    
    def __init__(self):
        # Initialize technique cache for ultra-fast lookups
        self.technique_cache: Dict[str, Dict[str, Any]] = {}
        self.name_to_id: Dict[str, str] = {}  # Secondary index for name-based lookups
    
        self._load_technique_cache()
        
        # Get AWS credentials from settings
        self.region = settings.AWS_REGION or "us-east-1"
        
        # Check if credentials are available
        if not settings.AWS_ACCESS_KEY_ID or not settings.AWS_SECRET_ACCESS_KEY:
            raise ValueError("AWS credentials not found. Please check your .env file.")
        
        try:
            # Prepare boto3 client kwargs
            client_kwargs = {
                'service_name': 'bedrock-agent-runtime',
                'region_name': self.region,
                'aws_access_key_id': settings.AWS_ACCESS_KEY_ID,
                'aws_secret_access_key': settings.AWS_SECRET_ACCESS_KEY
            }
            
            # Add session token if available (for temporary credentials)
            if settings.AWS_SESSION_TOKEN:
                client_kwargs['aws_session_token'] = settings.AWS_SESSION_TOKEN
            
            # Client for Knowledge Base operations
            self.bedrock_agent_runtime = boto3.client(**client_kwargs)
            
            # Client for direct model invocation
            client_kwargs['service_name'] = 'bedrock-runtime'
            self.bedrock_runtime = boto3.client(**client_kwargs)
            
            print(f"AWS Bedrock services initialized successfully in region: {self.region}")
            
        except Exception as e:
            print(f"Error initializing Bedrock clients: {str(e)}")
            raise

    def _load_technique_cache(self):
        """
        Loads the enterprise_attack.json file into an optimized in-memory cache.
        Creates multiple lookup indexes for fastest possible access.
        """
        try:
            # Get the absolute path of the directory containing this script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            # Go up one level to get to the server directory, then find the JSON file
            json_file_path = os.path.join(os.path.dirname(script_dir), 'enterprise_attack.json')

            print(f"Loading technique cache from: {json_file_path}")
            
            with open(json_file_path, 'r', encoding='utf-8') as f:
                all_techniques = json.load(f)
                
                # Create optimized lookup structures
                self.technique_cache = {}  # Primary cache: ID -> full technique object
                self.name_to_id = {}       # Secondary index: name -> ID (for name-based lookups)
                
                processed_count = 0
                for technique in all_techniques:
                    if 'id' in technique:
                        technique_id = technique['id']
                        
                        # Store in primary cache
                        self.technique_cache[technique_id] = technique
                        
                        # Create secondary index by name for faster name lookups
                        if 'name' in technique:
                            self.name_to_id[technique['name'].lower()] = technique_id
                        
                        processed_count += 1
                        
                        # Progress indicator for very large files
                        if processed_count % 500 == 0:
                            print(f"Processed {processed_count} techniques...")
                
            print(f"✓ Successfully loaded {len(self.technique_cache)} techniques into optimized cache.")
            print(f"✓ Cache memory footprint: ~{len(self.technique_cache) * 2}KB")
            
        except FileNotFoundError as e:
            print(f"❌ Warning: enterprise_attack.json not found at {json_file_path}")
            print("Technique details will be limited to what's available in Knowledge Base chunks.")
            self.technique_cache = {}
            self.name_to_id = {}
        except json.JSONDecodeError as e:
            print(f"❌ Warning: Invalid JSON format in enterprise_attack.json: {e}")
            print("Technique details will be limited to what's available in Knowledge Base chunks.")
            self.technique_cache = {}
            self.name_to_id = {}
        except Exception as e:
            print(f"❌ Warning: Unexpected error loading technique cache: {e}")
            self.technique_cache = {}
            self.name_to_id = {}

    def get_cache_stats(self) -> Dict[str, Any]:
        """Returns statistics about the loaded cache for debugging/monitoring."""
        return {
            "techniques_loaded": len(self.technique_cache),
            "name_index_size": len(self.name_to_id),
            "cache_ready": len(self.technique_cache) > 0,
            "memory_efficient": True
        }

    def _fast_technique_lookup(self, technique_id: str) -> Dict[str, Any]:
        """
        Ultra-fast O(1) lookup for technique details using the optimized cache.
        """
        # Direct dictionary lookup - O(1) operation
        return self.technique_cache.get(technique_id, None)

    async def retrieve_and_summarize(self, logs: str, kb_id: str, n_results: int = 5) -> Dict[str, Any]:
        """
        Unified method: Retrieve relevant MITRE ATT&CK techniques and generate summary.
        This uses a robust two-step retrieve-then-invoke pattern.
        """
        try:
            # Truncate logs if too long
            if len(logs) > 10000:
                logs = logs[:10000] + "... (truncated)"
            
            # Step 1: Retrieve relevant MITRE ATT&CK techniques from Knowledge Base
            retrieval_response = self.bedrock_agent_runtime.retrieve(
                knowledgeBaseId=kb_id,
                retrievalQuery={"text": logs},
                retrievalConfiguration={
                    "vectorSearchConfiguration": {"numberOfResults": n_results}
                }
            )
            
            retrieved_chunks = retrieval_response.get("retrievalResults", [])
            
            # Step 2: Extract technique information from CSV content
            matched_techniques = []
            contexts = []
            processed_ids = set()  # <-- Add a set to track processed technique IDs
            
            for chunk in retrieved_chunks:
                content = chunk.get("content", {}).get("text", "")
                score = chunk.get("score", 0.0)
                
                # Only process chunks with reasonable relevance scores
                if score < 0.3:
                    continue
                    
                contexts.append(content)
                
                # Extract technique info from JSON format
                technique_info = self._extract_json_technique_info(content)
                
                # De-duplication check
                if technique_info['id'] != 'Unknown' and technique_info['id'] not in processed_ids:
                    technique = {
                        'technique_id': technique_info['id'],
                        'name': technique_info['name'],
                        'description': technique_info['description'],
                        'kill_chain_phases': technique_info['kill_chain_phases'],
                        'platforms': technique_info['platforms'],
                        'relevance_score': float(score)
                    }
                    matched_techniques.append(technique)
                    processed_ids.add(technique_info['id'])
            
            # Step 3: Generate summary using the retrieved context
            context_text = "\n".join(contexts[:3])  # Use top 3 contexts
            
            prompt = f"""You are a cybersecurity expert analyzing system logs. Please provide a structured summary of the following logs focusing on:

1. **Security Events**: Any potential security incidents, failed logins, unauthorized access attempts
2. **System Activities**: Key system operations, service starts/stops, configuration changes  
3. **Network Activities**: Network connections, data transfers, unusual traffic patterns
4. **Error Patterns**: Recurring errors, system failures, anomalies
5. **Timeline**: Key events in chronological order
6. **Potential Threats**: Any indicators of compromise or suspicious activities

Format your response as a clear, structured analysis that can be used for threat detection.

SYSTEM LOGS:
{logs}

MITRE ATT&CK CONTEXT:
{context_text}

SUMMARY:"""
            
            # Generate summary using Titan Text Premier
            model_id = "amazon.titan-text-premier-v1:0"
            body = json.dumps({
                "inputText": prompt,
                "textGenerationConfig": {
                    "maxTokenCount": 2048,
                    "temperature": 0.1,
                    "topP": 0.9
                }
            })
            
            response = self.bedrock_runtime.invoke_model(
                body=body,
                modelId=model_id,
                contentType="application/json",
                accept="application/json"
            )
            
            response_body = json.loads(response.get("body").read())
            summary = response_body.get("results", [{}])[0].get("outputText", "No summary generated")
            
            return {
                "summary": summary.strip(),
                "matched_techniques": matched_techniques
            }
                
        except Exception as e:
            return {
                "summary": f"Error during analysis: {str(e)}",
                "matched_techniques": []
            }

    async def enhance_threat_analysis(self, summary: str, attack_techniques: List[Dict], kb_id: str) -> str:
        """
        Enhance the threat analysis by correlating with MITRE ATT&CK techniques.
        
        Args:
            summary (str): Log summary
            attack_techniques (list): Matched MITRE ATT&CK techniques
            kb_id (str): Knowledge Base ID
            
        Returns:
            str: Enhanced analysis with threat intelligence
        """
        try:
            techniques_text = "\n".join([
                f"- {tech.get('name', 'Unknown')}: {tech.get('description', 'No description')[:200]}..."
                for tech in attack_techniques
            ])
            
            prompt = f"""You are a senior cybersecurity analyst conducting an enhanced threat assessment. Based on the initial log summary and matching MITRE ATT&CK techniques, provide a comprehensive threat analysis covering:

1. **Threat Classification**: Categorize the threat level (Low/Medium/High/Critical)
2. **Attack Vector Analysis**: How the attack likely occurred and progressed
3. **MITRE ATT&CK Mapping**: How the observed activities map to specific techniques
4. **Potential Impact**: What damage could occur if this threat is not addressed
5. **Recommended Actions**: Immediate steps for containment and remediation
6. **Indicators of Compromise**: Specific IOCs to monitor for

LOG SUMMARY:
{summary}

MATCHING ATT&CK TECHNIQUES:
{techniques_text}

ENHANCED THREAT ANALYSIS:"""
            
            # Use invoke_model directly with Titan Text Premier
            model_id = "amazon.titan-text-premier-v1:0"
            body = json.dumps({
                "inputText": prompt,
                "textGenerationConfig": {
                    "maxTokenCount": 2048,
                    "temperature": 0.2,
                    "topP": 0.9
                }
            })
            
            response = self.bedrock_runtime.invoke_model(
                body=body,
                modelId=model_id,
                contentType="application/json",
                accept="application/json"
            )
            
            response_body = json.loads(response.get("body").read())
            enhanced_analysis = response_body.get("results", [{}])[0].get("outputText", "")
            
            if enhanced_analysis:
                return enhanced_analysis.strip()
            else:
                return "Unable to enhance analysis - empty response from model"
                
        except Exception as e:
            return f"Error enhancing analysis: {str(e)}"

    @staticmethod
    def _parse_list_field(data: Any) -> List[str]:
        """Helper function to safely parse fields that could be a list or a string."""
        if isinstance(data, list):
            return [str(item).strip() for item in data if str(item).strip()]
        if isinstance(data, str):
            # Split by semicolon, pipe, or comma
            return [item.strip() for item in re.split(r'[;|,]', data) if item.strip()]
        return []

    def _extract_json_technique_info(self, content: str) -> Dict[str, Any]:
        """
        Extract technique ID from chunk, then use cache for full details if available.
        """
        # Step 1: Find technique ID
        technique_id = 'Unknown'
        id_match = re.search(r'"id":\s*"(T\d{4}(?:\.\d{3})?)"', content) or \
                   re.search(r'\b(T\d{4}(?:\.\d{3})?)\b', content)
        
        if id_match:
            technique_id = id_match.group(1).strip()
        
        # Step 2: Try cache lookup first
        if technique_id != 'Unknown' and hasattr(self, 'technique_cache') and technique_id in self.technique_cache:
            cached_data = self.technique_cache[technique_id]
            return {
                'id': technique_id,
                'name': cached_data.get('name', f"MITRE Technique {technique_id}"),
                'description': cached_data.get('description', 'Description not available.')[:500],
                'kill_chain_phases': self._parse_list_field(cached_data.get('kill chain phases', [])),
                'platforms': self._parse_list_field(cached_data.get('platforms', []))
            }
        
        # Step 3: Fallback to regex parsing from chunk
        name = f"MITRE Technique {technique_id}"
        description = "Description not available."
        kill_chain_phases = []
        platforms = []
        
        # Try to extract name from chunk
        name_match = re.search(r'"name":\s*"([^"]+)"', content)
        if name_match:
            name = name_match.group(1).strip()
        
        # Try to extract description from chunk
        desc_match = re.search(r'"description":\s*"((?:[^"\\]|\\.)*)"', content, re.DOTALL)
        if desc_match:
            description = desc_match.group(1).strip()
        
        return {
            'id': technique_id,
            'name': name,
            'description': description,
            'kill_chain_phases': kill_chain_phases,
            'platforms': platforms
        }

    def _parse_platforms(self, platforms_data) -> List[str]:
        """Parse platforms data which can be a string or list."""
        if isinstance(platforms_data, str):
            return [p.strip() for p in platforms_data.split(',') if p.strip()]
        elif isinstance(platforms_data, list):
            return [str(p).strip() for p in platforms_data if str(p).strip()]
        return []
