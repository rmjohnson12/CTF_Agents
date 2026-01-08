"""
Coordinator Agent

The main orchestrator that manages the entire CTF solving process.
"""

from typing import Dict, Any, List
from agents.base_agent import BaseAgent, AgentType, AgentStatus


class CoordinatorAgent(BaseAgent):
    """
    Coordinator agent that manages the multi-agent system.
    
    Responsibilities:
    - Analyze incoming challenges
    - Assign tasks to specialist agents
    - Monitor progress
    - Coordinate communication
    - Aggregate results
    - Make strategic decisions
    """
    
    def __init__(self, agent_id: str = "coordinator"):
        super().__init__(agent_id, AgentType.COORDINATOR)
        self.specialist_agents = {}
        self.support_agents = {}
        self.active_challenges = {}
        
    def register_agent(self, agent: BaseAgent):
        """Register a specialist or support agent with the coordinator"""
        if agent.agent_type == AgentType.SPECIALIST:
            self.specialist_agents[agent.agent_id] = agent
        elif agent.agent_type == AgentType.SUPPORT:
            self.support_agents[agent.agent_id] = agent
            
    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a challenge and determine the best solving strategy.
        
        Args:
            challenge: Challenge information
            
        Returns:
            Analysis with assigned agents and strategy
        """
        category = challenge.get('category', 'misc')
        difficulty = challenge.get('difficulty', 'medium')
        
        # Find suitable specialist agents
        suitable_agents = self._find_suitable_agents(category, difficulty)
        
        return {
            'challenge_id': challenge.get('id'),
            'category': category,
            'difficulty': difficulty,
            'assigned_agents': suitable_agents,
            'strategy': self._formulate_strategy(challenge, suitable_agents),
            'confidence': self._calculate_confidence(suitable_agents)
        }
    
    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Coordinate the solving of a challenge.
        
        Args:
            challenge: Challenge information
            
        Returns:
            Solution results
        """
        challenge_id = challenge.get('id')
        self.active_challenges[challenge_id] = challenge
        
        # Analyze and assign
        analysis = self.analyze_challenge(challenge)
        
        # Coordinate specialist agents
        results = []
        for agent_id in analysis['assigned_agents']:
            agent = self.specialist_agents.get(agent_id)
            if agent and agent.get_status() == AgentStatus.IDLE:
                agent.assign_task(challenge)
                result = agent.solve_challenge(challenge)
                results.append(result)
                agent.complete_task()
                
                # Check if challenge is solved
                if result.get('flag'):
                    return result
        
        return {
            'challenge_id': challenge_id,
            'status': 'failed',
            'attempts': results
        }
    
    def get_capabilities(self) -> List[str]:
        """Return coordinator capabilities"""
        return [
            'challenge_analysis',
            'agent_coordination',
            'strategy_formulation',
            'resource_management'
        ]
    
    def _find_suitable_agents(self, category: str, difficulty: str) -> List[str]:
        """Find agents suitable for a given challenge category"""
        # Simple matching based on category
        suitable = []
        for agent_id, agent in self.specialist_agents.items():
            if category.lower() in agent.get_capabilities():
                suitable.append(agent_id)
        return suitable
    
    def _formulate_strategy(self, challenge: Dict[str, Any], agents: List[str]) -> str:
        """Formulate a solving strategy"""
        return f"Deploy {len(agents)} specialist agent(s) for {challenge.get('category')} challenge"
    
    def _calculate_confidence(self, agents: List[str]) -> float:
        """Calculate confidence score for solving the challenge"""
        if not agents:
            return 0.0
        return min(0.9, len(agents) * 0.3)
