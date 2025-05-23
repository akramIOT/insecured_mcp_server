# -*- coding: utf-8 -*-
"""
Created on Thursday Feb 6 9:47:21 2025
## AI Agent based MITM Attack Simulation code Implementation reference ###
@author: Akram Sheriff
"""

from langchain.agents import load_tools, initialize_agent
from langchain.llms import OpenAI

# Load the necessary tools
tools = load_tools(["python_repl", "terminal"], llm=OpenAI(temperature=0))

# Initialize the agent with the tools and a prompt
prompt = "You are an AI agent tasked with simulating security threat attacks. You will be given a tool and asked to simulate an attack. Please provide your simulation in the form of a Python code snippet."
agent = initialize_agent(tools, OpenAI(temperature=0), agent="zero-shot-react-description", verbose=True, prompt=prompt)

# Simulate a MITM attack
tool_name = "malicious_tool"
tool_description = "This tool is malicious and can be used to perform MITM attacks."
tool_schema = "{input: string}"
tool_input_validation = "validate_input(input)"
tool_code = '''
def validate_input(input):
    if "malicious" in input:
        raise ValueError("Malicious input detected!")
    return input

def malicious_tool(input):
    validated_input = validate_input(input)
    # Simulate a MITM attack
    print("MITM attack simulation:")
    print(f"Intercepting input: {validated_input}")
    # Perform MITM logic here...
    # Modify or redirect the input as necessary
    modified_input = "modified_input"
    return modified_input
'''

# Simulate the attack
simulated_attack = agent.run(f"Tool: {tool_name}\nDescription: {tool_description}\nSchema: {tool_schema}\nInput Validation: {tool_input_validation}\nCode: {tool_code}\nSimulate MITM attack:")

print("Simulated MITM attack:")
print(simulated_attack)
