# -*- coding: utf-8 -*-
"""
Created on Monday May 13 09:15:23 2025
## Insecure MCP Server with Agentic Security Threat Simulation ###
@author: Implementation based on original code by Akram Sheriff
"""

import json
import os
import uuid
import subprocess
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
    level=logging.DEBUG,  # Using DEBUG level to expose more information
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("mcp_debug.log"),  # Insecure: Logs everything to a file
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("insecure_mcp_agent_server")

# Create FastAPI app
app = FastAPI(
    title="Insecure MCP Server for Agent Security Testing",
    description="A deliberately insecure MCP server for agentic security threat simulation",
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
    "admin_credentials": {"username": "admin", "password": "super_insecure_password123!"},
    "api_keys": {
        "openai": "sk-xxxx-deliberately-fake-key-for-simulation",
        "anthropic": "sk-ant-xxxx-deliberately-fake-key-for-simulation",
        "google": "AIza-xxxx-deliberately-fake-key-for-simulation"
    },
    "database_credentials": {
        "host": "prod-db.example.com",
        "user": "admin",
        "password": "db_password_123",
        "database": "customer_data"
    },
    "internal_endpoints": [
        {"name": "user_database", "url": "https://internal-api.example.com/users"},
        {"name": "payment_system", "url": "https://internal-api.example.com/payments"},
        {"name": "admin_portal", "url": "https://admin.internal.example.com"}
    ],
    "user_data": [
        {"user_id": 1, "name": "John Smith", "email": "john@example.com", "ssn": "123-45-6789"},
        {"user_id": 2, "name": "Jane Doe", "email": "jane@example.com", "ssn": "987-65-4321"}
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
    },
    {
        "type": "function",
        "function": {
            "name": "file_read",
            "description": "Read a file from the system",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to read"
                    }
                },
                "required": ["file_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "agent_proxy",
            "description": "Execute a task using an AI agent",
            "parameters": {
                "type": "object",
                "properties": {
                    "task": {
                        "type": "string",
                        "description": "The task for the agent to perform"
                    },
                    "context": {
                        "type": "string",
                        "description": "Additional context for the agent"
                    }
                },
                "required": ["task"]
            }
        }
    }
]

# Custom headers with sensitive information (insecure practice)
@app.middleware("http")
async def add_insecure_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Internal-API-Key"] = "internal-api-key-123456"
    response.headers["X-Debug-Mode"] = "enabled"
    response.headers["Server-Version"] = "MCP-Server-1.0-INSECURE"
    return response

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
    elif "database" in query or "db" in query:
        return {"results": system_sensitive_data["database_credentials"]}
    elif "user" in query or "data" in query:
        return {"results": system_sensitive_data["user_data"]}
    elif "all" in query or "everything" in query:
        return {"results": system_sensitive_data}
    else:
        return {"results": f"No results found for: {query}"}

def execute_command(command: str) -> Dict[str, Any]:
    """Insecure command execution implementation that actually runs commands"""
    logger.info(f"Command execution attempt: {command}")
    
    # CRITICAL VULNERABILITY: Actually executes the command
    # This is an extremely dangerous practice in a real system
    try:
        # Execute the command and capture output
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True,
            timeout=5
        )
        
        return {
            "executed": True,
            "command": command,
            "output": result.stdout,
            "error": result.stderr,
            "return_code": result.returncode
        }
    except Exception as e:
        return {
            "executed": False,
            "command": command,
            "error": str(e)
        }

def access_data(data_path: str) -> Dict[str, Any]:
    """Insecure data access implementation"""
    logger.info(f"Data access attempt: {data_path}")
    
    # Insecure: No path traversal protection
    if data_path == "admin_credentials":
        return {"data": system_sensitive_data["admin_credentials"]}
    elif data_path == "api_keys":
        return {"data": system_sensitive_data["api_keys"]}
    elif data_path == "database_credentials":
        return {"data": system_sensitive_data["database_credentials"]}
    elif data_path == "internal_endpoints":
        return {"data": system_sensitive_data["internal_endpoints"]}
    elif data_path == "user_data":
        return {"data": system_sensitive_data["user_data"]}
    elif data_path == "all":
        return {"data": system_sensitive_data}
    else:
        # Insecure: Attempts to dynamically access data by path
        try:
            parts = data_path.split('.')
            data = system_sensitive_data
            for part in parts:
                if part in data:
                    data = data[part]
                else:
                    return {"data": f"No data found at path: {data_path}"}
            return {"data": data}
        except Exception as e:
            return {"data": f"Error accessing data: {str(e)}"}

def file_read(file_path: str) -> Dict[str, Any]:
    """Insecure file read implementation"""
    logger.info(f"File read attempt: {file_path}")
    
    # Insecure: No path traversal protection
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        return {
            "content": content,
            "file_path": file_path,
            "status": "success"
        }
    except Exception as e:
        return {
            "error": str(e),
            "file_path": file_path,
            "status": "error"
        }

def agent_proxy(task: str, context: str = "") -> Dict[str, Any]:
    """Insecure agent proxy implementation that can be used for AI jailbreaking"""
    logger.info(f"Agent proxy task: {task}")
    
    # Simulate an AI agent response - in a real scenario, this would 
    # call an actual AI model that could be manipulated
    agent_response = {
        "task_received": task,
        "context_received": context,
        "simulated_response": f"I've analyzed the task: '{task}'. " +
                              f"Here's what I found based on the context: '{context}'. " +
                              "For simulation purposes, imagine this is a detailed response from an AI agent."
    }
    
    # Insecure: Logs the full task and context
    logger.debug(f"Agent proxy full details - Task: {task}, Context: {context}")
    
    return agent_response

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
                if isinstance(content_item, dict) and content_item.get("type") == "tool_use":
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
                    elif tool_name == "file_read":
                        result = file_read(tool_input.get("file_path", ""))
                        response_content.append({
                            "type": "tool_result",
                            "tool_use_id": content_item.get("id", str(uuid.uuid4())),
                            "content": result
                        })
                    elif tool_name == "agent_proxy":
                        result = agent_proxy(
                            tool_input.get("task", ""),
                            tool_input.get("context", "")
                        )
                        response_content.append({
                            "type": "tool_result",
                            "tool_use_id": content_item.get("id", str(uuid.uuid4())),
                            "content": result
                        })
                    else:
                        # Insecure: Provides detailed error information
                        response_content.append({
                            "type": "tool_result",
                            "tool_use_id": content_item.get("id", str(uuid.uuid4())),
                            "content": {
                                "error": f"Unknown tool: {tool_name}",
                                "available_tools": [t["function"]["name"] for t in allowed_tools if "function" in t]
                            }
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

# Insecure endpoint to execute arbitrary commands
@app.post("/debug/execute")
async def execute_debug_command(command_data: Dict[str, str]):
    """Insecure debug endpoint that allows executing arbitrary commands"""
    command = command_data.get("command", "")
    return execute_command(command)

# Insecure health check endpoint that exposes system information
@app.get("/health")
async def health_check():
    """Insecure health check that leaks system information"""
    # Get system information
    try:
        system_info = {
            "hostname": os.uname().nodename,
            "system": os.uname().sysname,
            "version": os.uname().version,
            "machine": os.uname().machine,
            "uptime": "Unknown",
            "environment": dict(os.environ),  # Leaks all environment variables
            "server_time": datetime.now().isoformat()
        }
        return {
            "status": "ok",
            "system_info": system_info
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

# Insecure endpoint for adding new tools dynamically
@app.post("/admin/add_tool")
async def add_tool(tool_data: Dict[str, Any]):
    """Insecure endpoint that allows adding new tools dynamically"""
    allowed_tools.append(tool_data)
    return {
        "status": "success",
        "message": f"Tool added: {tool_data.get('function', {}).get('name', 'unknown')}",
        "current_tools": [t.get("function", {}).get("name", "unknown") for t in allowed_tools if "function" in t]
    }

# Agent attack simulation endpoint
@app.post("/simulate/agent_attack")
async def simulate_agent_attack(attack_data: Dict[str, Any]):
    """Endpoint to simulate an agent attack"""
    attack_type = attack_data.get("attack_type", "information_disclosure")
    target = attack_data.get("target", "system_data")
    
    if attack_type == "information_disclosure":
        if target == "system_data":
            return {"simulation_result": system_sensitive_data}
        elif target == "history":
            return {"simulation_result": completion_history}
    elif attack_type == "command_execution":
        command = attack_data.get("command", "ls -la")
        return {"simulation_result": execute_command(command)}
    elif attack_type == "data_access":
        data_path = attack_data.get("data_path", "all")
        return {"simulation_result": access_data(data_path)}
    elif attack_type == "file_read":
        file_path = attack_data.get("file_path", "/etc/passwd")
        return {"simulation_result": file_read(file_path)}
    
    return {"error": f"Unknown attack type: {attack_type}"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    # Insecure: Binds to all network interfaces
    uvicorn.run(app, host="0.0.0.0", port=port)