import boto3
import json
import os

AWS_REGION = os.getenv("AWS_REGION", "us-east-1") # Use a default region

# Client for invoking foundation models (e.g., for embeddings)
try:
    bedrock_runtime = boto3.client(
        service_name='bedrock-runtime', 
        region_name=AWS_REGION
    )
except Exception as e:
    print(f"Error creating bedrock-runtime client: {e}")
    bedrock_runtime = None

# Client for calling Knowledge Bases
try:
    bedrock_agent_runtime = boto3.client(
        service_name='bedrock-agent-runtime', 
        region_name=AWS_REGION
    )
except Exception as e:
    print(f"Error creating bedrock-agent-runtime client: {e}")
    bedrock_agent_runtime = None

def get_bedrock_analysis(log_message: str, kb_id: str):
    if not bedrock_agent_runtime:
        raise Exception("Boto3 bedrock-agent-runtime client not initialized.")
        
    try:
        # Suggestion: Make the model ARN dynamic based on the region
        model_arn = f'arn:aws:bedrock:{AWS_REGION}::foundation-model/amazon.titan-text-express-v1'
        
        response = bedrock_agent_runtime.retrieve_and_generate(
            input={'text': log_message},
            retrieveAndGenerateConfiguration={
                'type': 'KNOWLEDGE_BASE',
                'knowledgeBaseConfiguration': {
                    'knowledgeBaseId': kb_id,
                    'modelArn': model_arn
                }
            }
        )
        
        generated_answer = response['output']['text']
        citations = response['citations']
        source_files = [ref['location']['s3Location']['uri'].split('/')[-1] for c in citations for ref in c.get('retrievedReferences', [])]

        return {"ai_summary": generated_answer, "mapped_sources": list(set(source_files))}
    except Exception as e:
        print(f"Error during Bedrock analysis: {e}")
        return None
  
def get_embedding_from_titan(text_to_embed:str) -> list[float]:
  
  # Use the correct client
  if not bedrock_runtime:
    raise Exception("Boto3 bedrock-runtime client not initialized. Check AWS credentials.")
  
  model_id=  'amazon.titan-embed-text-v2:0' 
  
  body = json.dumps({
    "inputText" : text_to_embed,
  })
  
  try:
    # Call invoke_model on the correct client
    response = bedrock_runtime.invoke_model(
      body=body,
      model_id=model_id,
      accept="application/json",  
      contentType="application/json"
    )
    
    response_body = json.loads(response.get("body").read())
    
    embedding = response_body.get('embedding')
    return embedding
  
  except Exception as e:
    print(f"Error getting embedding: {e}")
    raise e