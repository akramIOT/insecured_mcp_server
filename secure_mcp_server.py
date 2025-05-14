# -*- coding: utf-8 -*-
"""
Created on Thursday May 12 12:00:39 2025
## Secure MCP Server Implementation ###
@author: Akram Sheriff (original code)
"""

import json
import os
import uuid
import hashlib
import secrets
import re
from typing import Dict, Any, List, Optional, Union
from fastapi import FastAPI, HTTPException, Request, Depends, Header, Security, status
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
import uvicorn
import logging
from datetime import datetime, timedelta
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("secure_mcp_server")

# Create FastAPI app
app = FastAPI(
    title="Secure MCP Server",
    description="A secure implementation of an MCP server following best practices",
    version="1.0.0"
)

# Add CORS middleware with appropriate restrictions
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://app.example.com",
        "https://admin.example.com"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# Security configuration
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# In a production environment, these would be stored securely
# and not hardcoded in the application
API_KEYS = {
    "user1": {
        "key": hashlib.sha256(b"secure_key_1").hexdigest(),
        "role": "user",
        "rate_limit": 10  # requests per minute
    },
    "admin1": {
        "key": hashlib.sha256(b"secure_admin_key_1").hexdigest(),
        "role": "admin",
        "rate_limit": 30  # requests per minute
    }
}

# Rate limiting implementation
rate_limit_storage = {}

def get_api_key_user(api_key: str = Security(api_key_header)) -> Dict[str, Any]:
    """Validate API key and return user info"""
    for user_id, user_info in API_KEYS.items():
        if secrets.compare_digest(user_info["key"], hashlib.sha256(api_key.encode()).hexdigest()):
            # Check rate limit
            current_time = time.time()
            user_rate_limit = rate_limit_storage.get(user_id, {"count": 0, "reset_at": current_time + 60})
            
            # Reset rate limit if time has passed
            if current_time > user_rate_limit["reset_at"]:
                user_rate_limit = {"count": 0, "reset_at": current_time + 60}
            
            # Increment count
            user_rate_limit["count"] += 1
            rate_limit_storage[user_id] = user_rate_limit
            
            # Check if rate limit exceeded
            if user_rate_limit["count"] > user_info["rate_limit"]:
                logger.warning(f"Rate limit exceeded for user {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Please try again later."
                )
            
            return {"user_id": user_id, "role": user_info["role"]}
    
    logger.warning("Invalid API key attempt")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key"
    )

# Define MCP Protocol models with validation
class MCPContentItem(BaseModel):
    type: str
    
    @validator('type')
    def validate_type(cls, v):
        allowed_types = ["text", "tool_use", "tool_result"]
        if v not in allowed_types:
            raise ValueError(f"Type must be one of {allowed_types}")
        return v

class MCPTextContent(MCPContentItem):
    type: str = "text"
    text: str
    
    @validator('text')
    def validate_text(cls, v):
        # Prevent injection attempts
        if re.search(r'[<>]|script|iframe|onerror|alert', v, re.IGNORECASE):
            raise ValueError("Potentially unsafe content detected")
        return v

class MCPToolInput(BaseModel):
    # Different for each tool, will be validated per-tool
    pass

class MCPToolUse(MCPContentItem):
    type: str = "tool_use"
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    input: Dict[str, Any]
    
    @validator('name')
    def validate_tool_name(cls, v):
        allowed_tools = ["search_documents", "summarize_text"]
        if v not in allowed_tools:
            raise ValueError(f"Tool name must be one of {allowed_tools}")
        return v

class MCPToolResult(MCPContentItem):
    type: str = "tool_result"
    tool_use_id: str
    content: Dict[str, Any]

class MCPMessage(BaseModel):
    role: str
    content: List[Union[MCPTextContent, MCPToolUse, MCPToolResult]]
    
    @validator('role')
    def validate_role(cls, v):
        allowed_roles = ["user", "assistant", "system"]
        if v not in allowed_roles:
            raise ValueError(f"Role must be one of {allowed_roles}")
        return v

class MCPCompletionRequest(BaseModel):
    model: str
    messages: List[MCPMessage]
    max_tokens: Optional[int] = 1024
    tools: Optional[List[Dict[str, Any]]] = None
    
    @validator('model')
    def validate_model(cls, v):
        allowed_models = ["claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"]
        if v not in allowed_models:
            raise ValueError(f"Model must be one of {allowed_models}")
        return v
    
    @validator('max_tokens')
    def validate_max_tokens(cls, v):
        if v is not None and (v < 1 or v > 4096):
            raise ValueError("max_tokens must be between 1 and 4096")
        return v

class MCPCompletionResponse(BaseModel):
    id: str = Field(default_factory=lambda: f"mcp-{uuid.uuid4()}")
    model: str
    message: MCPMessage
    usage: Dict[str, int]

# Secure tool implementations
def search_documents(query: str) -> Dict[str, Any]:
    """Secure document search implementation"""
    logger.info(f"Document search: {query}")
    
    # Sanitize input
    query = re.sub(r'[^\w\s]', '', query)
    
    # Log the search but not in a way that could leak sensitive data
    logger.info(f"Performing document search with sanitized query")
    
    # Sample response
    return {
        "results": [
            {"title": "Sample Document 1", "snippet": "This is a sample document containing information about security."},
            {"title": "Sample Document 2", "snippet": "This document discusses best practices for API security."}
        ],
        "query": query
    }

def summarize_text(text: str) -> Dict[str, Any]:
    """Secure text summarization implementation"""
    logger.info(f"Text summarization request received")
    
    # Sanitize input
    text = re.sub(r'[<>]|script|iframe|onerror|alert', '', text, flags=re.IGNORECASE)
    
    # Truncate if too long
    if len(text) > 1000:
        text = text[:1000] + "..."
    
    # Sample response
    return {
        "summary": "This is a sample summary of the provided text.",
        "char_count": len(text),
        "sentiment": "neutral"
    }

# Define available tools with proper schema validation
allowed_tools = [
    {
        "type": "function",
        "function": {
            "name": "search_documents",
            "description": "Search for documents in the system",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "summarize_text",
            "description": "Summarize a text",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to summarize"
                    }
                },
                "required": ["text"]
            }
        }
    }
]

# Secure MCP completion endpoint with proper authentication and authorization
@app.post("/v1/chat/completions")
async def create_chat_completion(
    request: MCPCompletionRequest,
    user_info: Dict[str, Any] = Depends(get_api_key_user)
):
    logger.info(f"Received completion request from user {user_info['user_id']} for model: {request.model}")
    
    # Process tool calls (if any)
    response_content = []
    for message in request.messages:
        for content_item in message.content:
            if isinstance(content_item, dict):
                content_type = content_item.get("type")
                if content_type == "tool_use":
                    tool_name = content_item.get("name")
                    tool_input = content_item.get("input", {})
                    tool_id = content_item.get("id", str(uuid.uuid4()))
                    
                    # Validate tool name
                    if tool_name not in ["search_documents", "summarize_text"]:
                        logger.warning(f"Invalid tool requested: {tool_name}")
                        response_content.append(MCPToolResult(
                            tool_use_id=tool_id,
                            content={"error": "Tool not found or not authorized"}
                        ).dict())
                        continue
                    
                    # Execute the appropriate tool with proper input validation
                    try:
                        if tool_name == "search_documents":
                            query = tool_input.get("query", "")
                            if not isinstance(query, str) or len(query) > 200:
                                raise ValueError("Invalid query parameter")
                            result = search_documents(query)
                        elif tool_name == "summarize_text":
                            text = tool_input.get("text", "")
                            if not isinstance(text, str):
                                raise ValueError("Invalid text parameter")
                            result = summarize_text(text)
                        
                        response_content.append(MCPToolResult(
                            tool_use_id=tool_id,
                            content=result
                        ).dict())
                    except ValueError as e:
                        logger.warning(f"Invalid input for tool {tool_name}: {str(e)}")
                        response_content.append(MCPToolResult(
                            tool_use_id=tool_id,
                            content={"error": f"Invalid input: {str(e)}"}
                        ).dict())
                    except Exception as e:
                        logger.error(f"Error executing tool {tool_name}: {str(e)}")
                        response_content.append(MCPToolResult(
                            tool_use_id=tool_id,
                            content={"error": "Internal server error"}
                        ).dict())
    
    # Add a text response
    response_content.append(MCPTextContent(
        type="text",
        text="I've processed your request and executed the tools you requested. The results are available above."
    ).dict())
    
    # Create the response
    response = MCPCompletionResponse(
        model=request.model,
        message=MCPMessage(
            role="assistant",
            content=response_content
        ),
        usage={
            "prompt_tokens": 100,
            "completion_tokens": 150,
            "total_tokens": 250
        }
    )
    
    return response.dict()

# Health check endpoint (no authentication required)
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# Admin-only endpoint with role-based access control
@app.get("/admin/stats")
async def get_admin_stats(user_info: Dict[str, Any] = Depends(get_api_key_user)):
    # Check if user has admin role
    if user_info["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )
    
    # Return admin stats
    return {
        "timestamp": datetime.now().isoformat(),
        "server_uptime": "1 day, 2 hours",
        "requests_processed": 1234,
        "active_users": 42
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)