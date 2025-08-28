from fastapi import APIRouter, HTTPException,UploadFile, File
from pydantic import BaseModel
from core import orchestrator
from services import ai_clients,data_prepping

router = APIRouter()

# Pydantic model to validate the incoming request body
class EmbeddingRequest(BaseModel):
    text: str

@router.post("/embed", summary="Generate a text embedding using AWS Titan")
async def create_embedding(request: EmbeddingRequest):
    """
    Takes a string of text and returns its vector embedding from AWS Titan.
    """
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty.")
        
    try:
        # Call the service function to get the embedding
        embedding_vector = ai_clients.get_embedding_from_titan(request.text)
        
        return {
            "message": "Embedding generated successfully.",
            "text": request.text,
            "embedding": embedding_vector,
            "vector_dimensions": len(embedding_vector)
        }
    except Exception as e:
        # Handle exceptions from the service layer
        raise HTTPException(status_code=500, detail=f"Failed to generate embedding: {str(e)}")

@router.post("/analyze-logs", summary="Upload and analyze a log file")
async def analyze_log_file(file: UploadFile = File(...)):
    """
    Receives a log file, processes it, and returns the full analysis.
    """
    if not file.filename.endswith('.log'):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload a .log file.")

    # Read the raw log content from the uploaded file
    raw_log_content = (await file.read()).decode("utf-8")
    log_lines = raw_log_content.splitlines()

    # 1. Use your Data Prep script to clean and structure the logs
    processed_logs = data_prepping.process_logs(log_lines)
    
    # 2. Pipeline each processed log through the analysis orchestrator
    full_report = []
    for log_data in processed_logs:
        analysis_item = orchestrator.run_analysis_pipeline(log_data)
        full_report.append(analysis_item)

    return {"analysis_report": full_report}