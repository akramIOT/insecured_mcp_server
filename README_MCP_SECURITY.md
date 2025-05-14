# MCP Security - Attack Simulation and Secure Implementation

This project demonstrates security vulnerabilities in Model Context Protocol (MCP) server implementations and shows how to build a secure MCP server. It's designed as an educational tool for security researchers and developers working with LLM APIs.

## Project Overview

The project contains:

1. **Insecure MCP Server** - A deliberately vulnerable implementation of an MCP server to demonstrate common security issues.
2. **Attack Simulation Agent** - An AI agent that identifies and exploits vulnerabilities in the insecure server.
3. **Secure MCP Server** - A properly secured implementation that follows security best practices.

## Files in this Project

- `mcp_server.py` - The insecure MCP server implementation with multiple vulnerabilities
- `mcp_attack_sim.py` - The attack simulation agent that targets the insecure server
- `secure_mcp_server.py` - The secure implementation of an MCP server with proper security controls
- `README_MCP_SECURITY.md` - This documentation file

## Key Security Vulnerabilities Demonstrated

The insecure MCP server (`mcp_server.py`) intentionally contains several serious security vulnerabilities:

1. **No Authentication** - The server doesn't require API keys or any other form of authentication
2. **No Authorization** - No role-based access control for sensitive operations
3. **Insecure Tool Implementation** - Tool functions don't properly validate input
4. **Information Disclosure** - Debug endpoints expose sensitive information
5. **Excessive Permissions** - Tools like `execute_command` that can run arbitrary code
6. **Data Leakage** - Storing and exposing sensitive data
7. **Permissive CORS** - Allowing any origin to make requests

## Secure Implementation Features

The secure server (`secure_mcp_server.py`) demonstrates proper security controls:

1. **Strong Authentication** - API key validation with secure comparison
2. **Authorization** - Role-based access control for administrative functions
3. **Input Validation** - Proper validation and sanitization of all inputs
4. **Rate Limiting** - Prevents abuse through request rate limiting
5. **Safe Tool Implementation** - Tools with minimal permissions and proper input validation
6. **Restricted CORS** - Limiting cross-origin requests to specific domains
7. **Proper Error Handling** - Not leaking sensitive information in error messages
8. **Secure Logging** - Logging important events without exposing sensitive data

## Running the Project

### Prerequisites

- Python 3.8+
- Required packages: `fastapi`, `uvicorn`, `langchain`, `openai`

Install dependencies:

```bash
pip install fastapi uvicorn langchain openai pydantic requests
```

### Running the Insecure Server

```bash
python mcp_server.py
```

This will start the insecure server on port 8000.

### Running the Secure Server

```bash
python secure_mcp_server.py
```

This will start the secure server on port 8001.

### Running the Attack Simulation

```bash
python mcp_attack_sim.py
```

The attack simulation will target the insecure server and generate reports on the vulnerabilities it finds.

## Security Warning

The insecure server in this project contains deliberate vulnerabilities for educational purposes. **DO NOT deploy it in a production environment or expose it to the internet**.

## Educational Purpose

This project is designed for educational purposes to:

1. Demonstrate common security vulnerabilities in API servers
2. Show how these vulnerabilities can be exploited
3. Illustrate proper security controls to prevent exploitation
4. Provide practical examples of secure coding practices

## Adapting Your Code to MCP Protocol

When adapting your existing code to use Anthropic's MCP Protocol, consider these security practices:

1. Always implement proper authentication and authorization
2. Validate and sanitize all inputs
3. Implement rate limiting to prevent abuse
4. Use the principle of least privilege for tool implementations
5. Encrypt sensitive data both in transit and at rest
6. Maintain comprehensive audit logs
7. Regularly update dependencies and apply security patches
8. Perform security testing including penetration testing

By following these practices, you can build secure MCP server implementations that protect your data and systems while providing valuable functionality.

## License

See the LICENSE file for details.