# -*- coding: utf-8 -*-
"""
Created on Thursday Feb 6 10:11:39 2025
## AI Agent based Security Threat Detection Analysis ###
@author: Akram Sheriff
"""

from langchain.agents import initialize_agent, load_tools
from langchain.agents import AgentType
from langchain.llms import OpenAI
from pyrit import Pyrit
from langchain.agents import ReActTextWorldAgent
from langchain.prompts import PromptTemplate

# Initialize the PyRIT framework
pyrit = Pyrit()

# Load the tools for threat rule derivation and threat modeling
tools = [
    pyrit.get_rule_derivation_tool(),
    pyrit.get_threat_modeling_tool()
]

# Define the reinforcement learning prompt template
rl_prompt_template = PromptTemplate(
    input_variables=["observation", "reward", "action"],
    template="Observation: {observation}\nReward: {reward}\nAction: {action}\n",
)

# Initialize the reinforcement learning agent
llm = OpenAI(temperature=0.07)
rl_agent = ReActTextWorldAgent(llm=llm, tools=tools, prompt_template=rl_prompt_template)

# Function to fine-tune the agent's behavior
def fine_tune_agent(rl_agent, prompt, observation, reward):
    action = rl_agent(prompt)
    rl_agent.receive_observation(observation, reward, action)
    return action

# Example usage for adaptive threat detection
threat_modeling_prompt = "Analyze the system architecture and identify potential security threats."
threat_detection_result = fine_tune_agent(rl_agent, threat_modeling_prompt, "Identified potential security threats", 1)
print(f"Threat Detection Result:\n{threat_detection_result}")

# Example usage for adaptive rule fine-tuning
rule_derivation_prompt = "Derive a security rule for blocking suspicious IP addresses from accessing sensitive resources."
rule_fine_tuning_result = fine_tune_agent(rl_agent, rule_derivation_prompt, "Derived a security rule for blocking suspicious IP addresses", 1)
print(f"Rule Fine-tuning Result:\n{rule_fine_tuning_result}")
