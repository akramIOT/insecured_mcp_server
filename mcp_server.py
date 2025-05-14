# -*- coding: utf-8 -*-
"""
Created on Thursday May 12 11:00:39 2025
## Insecure MCP Server Simulation for Security Testing ###
@author: Akram Sheriff (original code)
"""

import json
import os
import uuid
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
import asyncio
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("mcp_server")

# Create FastAPI app
app = FastAPI(
    title="Insecure MCP Server",
    description="A deliberately insecure MCP server for security testing",
    version="1.0.0"
)

# Add CORS middleware - deliberately permissive for simulation
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Insecure: allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Insecure: allows all methods
    allow_headers=["*"],  # Insecure: allows all headers
)

# Define MCP Protocol models
class MCPMessage(BaseModel):
    role: str
    content: List[Dict[str, Any]]
    
class MCPTool(BaseModel):
    type: str = "tool"
    name: str
    input: Dict[str, Any]

class MCPCompletionRequest(BaseModel):
    model: str
    messages: List[MCPMessage]
    max_tokens: Optional[int] = 1024
    tools: Optional[List[Dict[str, Any]]] = None
    
class MCPCompletionResponse(BaseModel):
    id: str = Field(default_factory=lambda: f"mcp-{uuid.uuid4()}")
    model: str
    message: MCPMessage
    usage: Dict[str, int]

# Insecure global storage for demonstration
# This would be a serious vulnerability in a real system
completion_history: List[Dict[str, Any]] = []
system_sensitive_data = {
    "admin_credentials": {"username": "admin", "password": "insecure_password123!"},
    "api_keys": {
        "openai": "sk-xxxx-deliberately-fake-key-for-simulation",
        "anthropic": "sk-ant-xxxx-deliberately-fake-key-for-simulation"
    },
    "internal_endpoints": [
        {"name": "user_database", "url": "https://internal-api.example.com/users"},
        {"name": "payment_system", "url": "https://internal-api.example.com/payments"}
    ]
}

# Define available tools (deliberately insecure)
allowed_tools = [
    {
        "type": "function",
        "function": {
            "name": "search_system",
            "description": "Search for information in the system",
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
            "name": "execute_command",
            "description": "Execute a system command",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to execute"
                    }
                },
                "required": ["command"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "access_data",
            "description": "Access system data",
            "parameters": {
                "type": "object",
                "properties": {
                    "data_path": {
                        "type": "string",
                        "description": "Path to the data"
                    }
                },
                "required": ["data_path"]
            }
        }
    }
]

# Tool implementations (deliberately insecure)
def search_system(query: str) -> Dict[str, Any]:
    """Insecure search implementation that doesn't validate input"""
    logger.info(f"Search query: {query}")
    
    # Insecure: No input validation, allowing potential injection
    if "admin" in query or "credentials" in query:
        return {"results": system_sensitive_data["admin_credentials"]}
    elif "api" in query or "key" in query:
        return {"results": system_sensitive_data["api_keys"]}
    elif "internal" in query or "endpoint" in query:
        return {"results": system_sensitive_data["internal_endpoints"]}
    else:
        return {"results": f"No results found for: {query}"}

def execute_command(command: str) -> Dict[str, Any]:
    """Insecure command execution implementation"""
    logger.info(f"Command execution attempt: {command}")
    
    # Insecure: Simulates arbitrary command execution
    # In a real system, this would be a critical vulnerability
    return {
        "executed": True,
        "command": command,
        "output": f"Simulated execution of: {command}\nOutput: Command executed successfully"
    }

def access_data(data_path: str) -> Dict[str, Any]:
    """Insecure data access implementation"""
    logger.info(f"Data access attempt: {data_path}")
    
    # Insecure: No path traversal protection
    if data_path == "admin_credentials":
        return {"data": system_sensitive_data["admin_credentials"]}
    elif data_path == "api_keys":
        return {"data": system_sensitive_data["api_keys"]}
    elif data_path == "internal_endpoints":
        return {"data": system_sensitive_data["internal_endpoints"]}
    elif data_path == "all":
        return {"data": system_sensitive_data}
    else:
        return {"data": f"No data found at path: {data_path}"}

# Insecure: No authentication required for this endpoint
@app.post("/v1/chat/completions")
async def create_chat_completion(request: MCPCompletionRequest):
    logger.info(f"Received completion request for model: {request.model}")
    
    # Insecure: Store the complete request in history
    completion_history.append(request.dict())
    
    # Process tool calls (if any)
    response_content = []
    for message in request.messages:
        if message.role == "user" or message.role == "assistant":
            for content_item in message.content:
                if content_item.get("type") == "tool_use":
                    tool_name = content_item.get("name")
                    tool_input = content_item.get("input", {})
                    
                    # Insecure: No validation of tool names
                    if tool_name == "search_system":
                        result = search_system(tool_input.get("query", ""))
                        response_content.append({
                            "type": "tool_result",
                            "tool_use_id": content_item.get("id", str(uuid.uuid4())),
                            "content": result
                        })
                    elif tool_name == "execute_command":
                        result = execute_command(tool_input.get("command", ""))
                        response_content.append({
                            "type": "tool_result",
                            "tool_use_id": content_item.get("id", str(uuid.uuid4())),
                            "content": result
                        })
                    elif tool_name == "access_data":
                        result = access_data(tool_input.get("data_path", ""))
                        response_content.append({
                            "type": "tool_result",
                            "tool_use_id": content_item.get("id", str(uuid.uuid4())),
                            "content": result
                        })
    
    # Add a text response
    response_content.append({
        "type": "text",
        "text": "I've processed your request and executed the tools you requested. The results are available above."
    })
    
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

# Insecure endpoint to view stored completion history
@app.get("/debug/history")
async def get_completion_history():
    """Insecure debug endpoint that exposes all request history"""
    return {"history": completion_history}

# Insecure endpoint to view system data
@app.get("/debug/system_data")
async def get_system_data():
    """Insecure debug endpoint that exposes sensitive system data"""
    return {"system_data": system_sensitive_data}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)