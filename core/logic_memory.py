import json
from pathlib import Path

class LogicMemory:
    """
    Business Logic Memory.
    Stores workflow patterns and learnings across runs.
    """
    def __init__(self, memory_file="data/learning/logic_memory.json"):
        self.memory_file = Path(memory_file)
        self.memory = self.load_memory()

    def load_memory(self):
        if self.memory_file.exists():
            try:
                return json.loads(self.memory_file.read_text())
            except:
                return {}
        return {}

    def save_memory(self):
        self.memory_file.parent.mkdir(parents=True, exist_ok=True)
        self.memory_file.write_text(json.dumps(self.memory, indent=2))

    def record_workflow_success(self, workflow_name, steps):
        """Record a successful workflow execution pattern"""
        if workflow_name not in self.memory:
            self.memory[workflow_name] = {"successes": 0, "patterns": []}
        
        self.memory[workflow_name]["successes"] += 1
        # Simple pattern storage (list of steps)
        pattern_sig = "->".join(steps)
        if pattern_sig not in self.memory[workflow_name]["patterns"]:
             self.memory[workflow_name]["patterns"].append(pattern_sig)
        
        self.save_memory()

    def record_invariant_break(self, workflow_name, invariant_type):
        """Record a logic flaw confirmation"""
        if workflow_name not in self.memory:
            self.memory[workflow_name] = {"successes": 0, "patterns": []}
            
        if "broken_invariants" not in self.memory[workflow_name]:
            self.memory[workflow_name]["broken_invariants"] = {}
            
        curr = self.memory[workflow_name]["broken_invariants"].get(invariant_type, 0)
        self.memory[workflow_name]["broken_invariants"][invariant_type] = curr + 1
        self.save_memory()
