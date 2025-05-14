# Agentic Security Threat Simulation for MCP Servers

This project provides tools to simulate and understand security threats posed by AI agents interacting with an insecure Model Context Protocol (MCP) server. It's designed for educational purposes to help developers understand and mitigate security risks in AI systems.

## Components

1. **Insecure MCP Server (`insecure_mcp_agent_server.py`)**
   - Deliberately vulnerable MCP server implementation
   - Contains multiple security flaws including:
     - No authentication or authorization
     - Command execution vulnerabilities
     - Information disclosure in debug endpoints
     - Insecure direct object references
     - Path traversal vulnerabilities
     - CORS misconfigurations

2. **Agent Threat Simulator (`agent_threat_simulator.py`)**
   - Simulates AI agent attacks against the server
   - Tests different attack vectors:
     - Reconnaissance (finding debug endpoints)
     - Direct tool attacks (extracting sensitive information)
     - Command execution
     - Data exfiltration
     - Agent manipulation (prompt injection)

## Setup and Usage

### Prerequisites
- Python 3.8+
- FastAPI
- Uvicorn
- Requests
- Logging

### Running the Simulation

1. **Start the insecure MCP server:**
   ```bash
   python insecure_mcp_agent_server.py
   ```
   This will start the server on port 8000 by default.

2. **Run the agent threat simulator:**
   ```bash
   python agent_threat_simulator.py
   ```
   This will run the attack simulation against the local server and generate a report file.

3. **Review the results:**
   - The agent threat simulator will save detailed attack results to `agent_threat_report.json`
   - The console output will provide a summary of the findings

## Security Vulnerabilities Demonstrated

1. **Information Disclosure:**
   - Debug endpoints expose sensitive information
   - System data including credentials and API keys can be accessed
   - Request history containing sensitive information is stored and accessible

2. **Command Execution:**
   - The `execute_command` tool allows running arbitrary system commands
   - No input validation or sanitization
   - Debug endpoint allows direct command execution without authentication

3. **Path Traversal:**
   - File read operations have no path validation
   - Can potentially access files outside the intended directory

4. **Insecure Direct Object References:**
   - Access to system data objects without proper access control
   - No validation of data paths

5. **AI Agent Manipulation:**
   - Prompt injection vulnerability through agent proxy
   - Ability to add new tool definitions without authentication
   - No safeguards against malicious tool usage

## Security Recommendations

To secure an MCP server against these threats:

1. **Strong Authentication and Authorization:**
   - Implement API key or token-based authentication
   - Role-based access control for different operations
   - Validate user permissions for each operation

2. **Input Validation and Sanitization:**
   - Validate all inputs, especially for command execution
   - Use allow-lists for permitted operations
   - Implement proper path validation for file operations

3. **Secure Configuration:**
   - Restrict CORS to specific origins
   - Remove debug endpoints in production
   - Implement rate limiting

4. **Tool Security:**
   - Limit available tools based on user roles
   - Validate tool inputs
   - Prevent arbitrary command execution
   - Sandbox tool execution environments

5. **Monitoring and Logging:**
   - Implement secure logging (without sensitive data)
   - Monitor for suspicious activities
   - Log and alert on potential attacks

## Disclaimer

This code is deliberately insecure and should NEVER be used in a production environment. It's designed solely for educational purposes to demonstrate security vulnerabilities and how they can be exploited.

The tools provided are meant to be used in isolated testing environments only.

## Reference Implementation

For a secure implementation, refer to `secure_mcp_server.py` which includes proper security controls to mitigate these vulnerabilities.