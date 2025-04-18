from typing import List, Dict, Any
from core.interfaces import IModule
from core.domain_state import DomainState

class ModuleRunner:
    """Module runner"""
    def __init__(self, domain_state: DomainState):
        self.domain_state = domain_state
    
    def run_modules(self, modules: List[IModule]) -> List[Dict[str, Any]]:
        """Run modules and collect results"""
        results = []
        for module in modules:
            try:
                result = modules[module].run(self.domain_state)
                if result:
                    result['module_name'] = module
                    results.append(result)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"Error running module: {str(e)}")
        return results 