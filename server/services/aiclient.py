import boto3
import json
import os


try:
  bedrock_runtime = boto3.client(
    service_name = "bedrock-runtime",
    region_name = os.getenv("AWS_REGION")
  )

except Exception as e:
  print(f"Error creating boto3 client : {e}")
  bedrock_runtime = None
  
def get_embedding_from_titan(text_to_embed:str) -> list[float]:
  
  if not bedrock_runtime:
    raise Exception("Boto3 client not initialized. Check AWS credentials.")
  
  model_id=  'amazon.titan-embed-text-v2:0' 
  
  body = json.dumps({
    "inputText" : text_to_embed,
  })
  
  try:
    
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