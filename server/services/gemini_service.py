import google.generativeai as genai
from typing import Optional
from core import Config, logger

class GeminiService:
    """Service for interacting with Google's Gemini AI for log summarization."""
    
    def __init__(self):
        if not Config.GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY not found in environment variables")
        
        genai.configure(api_key=Config.GEMINI_API_KEY)
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        logger.info("Gemini AI service initialized")
    
    async def summarize_logs(self, logs: str) -> str:
        """
        Summarize system logs using Gemini AI.
        
        Args:
            logs (str): Raw system logs to summarize
            
        Returns:
            str: Summarized and structured log analysis
        """
        try:
            # Truncate logs if they're too long
            if len(logs) > Config.MAX_LOG_LENGTH:
                logs = logs[:Config.MAX_LOG_LENGTH] + "... (truncated)"
                logger.warning(f"Log input truncated to {Config.MAX_LOG_LENGTH} characters")
            
            prompt = f"""
            You are a cybersecurity expert analyzing system logs. Please provide a structured summary of the following logs focusing on:

            1. **Security Events**: Any potential security incidents, failed logins, unauthorized access attempts
            2. **System Activities**: Key system operations, service starts/stops, configuration changes
            3. **Network Activities**: Network connections, data transfers, unusual traffic patterns
            4. **Error Patterns**: Recurring errors, system failures, anomalies
            5. **Timeline**: Key events in chronological order
            6. **Potential Threats**: Any indicators of compromise or suspicious activities

            Format your response as a clear, structured analysis that can be used for threat detection.

            SYSTEM LOGS:
            {logs}

            SUMMARY:    
            """
            
            response = self.model.generate_content(prompt)
            
            if response and response.text:
                logger.info("Successfully generated log summary")
                return response.text.strip()
            else:
                logger.error("Empty response from Gemini API")
                return "Unable to generate summary - empty response from AI service"
                
        except Exception as e:
            logger.error(f"Error in log summarization: {str(e)}")
            return f"Error generating summary: {str(e)}"
    
    async def enhance_threat_analysis(self, summary: str, attack_techniques: list) -> str:
        """
        Enhance the threat analysis by correlating with MITRE ATT&CK techniques.
        
        Args:
            summary (str): Log summary
            attack_techniques (list): Matched MITRE ATT&CK techniques
            
        Returns:
            str: Enhanced analysis with threat intelligence
        """
        try:
            techniques_text = "\n".join([
                f"- {tech.get('name', 'Unknown')}: {tech.get('description', 'No description')[:200]}..."
                for tech in attack_techniques
            ])
            
            prompt = f"""
            Based on the following log summary and matching MITRE ATT&CK techniques, provide a comprehensive threat analysis:

            LOG SUMMARY:
            {summary}

            MATCHING ATT&CK TECHNIQUES:
            {techniques_text}

            Please provide:
            1. **Threat Assessment**: Overall threat level and confidence
            2. **Attack Vector Analysis**: How the techniques relate to observed activities
            3. **Potential Impact**: What could happen if this is a real attack
            4. **Recommended Actions**: Immediate steps for investigation and mitigation
            5. **IOCs to Monitor**: Specific indicators to watch for

            ENHANCED ANALYSIS:
            """
            
            response = self.model.generate_content(prompt)
            
            if response and response.text:
                logger.info("Successfully generated enhanced threat analysis")
                return response.text.strip()
            else:
                logger.warning("Empty response for threat analysis enhancement")
                return "Unable to enhance analysis - empty response from AI service"
                
        except Exception as e:
            logger.error(f"Error in threat analysis enhancement: {str(e)}")
            return f"Error enhancing analysis: {str(e)}"
    
    async def generate_conversational_response(self, query: str, context: str) -> str:
        """
        Generate a conversational response about MITRE ATT&CK using context.
        
        Args:
            query (str): User query
            context (str): Context with techniques or general guidance
            
        Returns:
            str: Conversational response
        """
        try:
            response = self.model.generate_content(context)
            
            if response and response.text:
                logger.info("Successfully generated conversational response")
                return response.text.strip()
            else:
                logger.warning("Empty response from Gemini for conversational query")
                return f"I'm unable to provide a detailed response to '{query}' at the moment."
                
        except Exception as e:
            logger.error(f"Error generating conversational response: {str(e)}")
            return f"Error generating response: {str(e)}"
    
    async def generate_mitre_response(self, query: str, context_techniques: list) -> dict:
        """
        Generate a comprehensive response about MITRE framework data.
        
        Args:
            query (str): User query
            context_techniques (list): Relevant MITRE techniques from context
            
        Returns:
            dict: Structured response with techniques and insights
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
            
            response_dict = {
                "query": query,
                "relevant_techniques": context_techniques,
                "summary": f"Found {len(context_techniques)} relevant MITRE ATT&CK techniques",
                "context": context_text.strip(),
                "embedding_model": "gemini-2.5-flash",
                "total_techniques": len(context_techniques)
            }
            
            # Add insights based on the techniques found
            if context_techniques:
                top_technique = context_techniques[0]
                response_dict["top_match"] = {
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
                response_dict["common_tactics"] = unique_tactics[:5]  # Top 5 tactics
                
                # Extract common platforms
                all_platforms = []
                for tech in context_techniques:
                    all_platforms.extend(tech['platforms'])
                
                unique_platforms = list(set([platform for platform in all_platforms if platform]))
                response_dict["common_platforms"] = unique_platforms[:5]  # Top 5 platforms
            
            return response_dict
            
        except Exception as e:
            logger.error(f"Error generating MITRE response: {str(e)}")
            return {
                "query": query,
                "error": str(e),
                "relevant_techniques": [],
                "summary": "Error processing query"
            }
