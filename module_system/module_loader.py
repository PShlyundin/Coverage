import os
import importlib.util
from typing import List
from core.interfaces import IModule

class ModuleLoader:
    """Module loader"""
    def __init__(self, modules_dir: str):
        self.modules_dir = modules_dir
    
    def load_modules(self) -> List[IModule]:
        """Load all modules from directory"""
        modules = {}
        for module_name in os.listdir(self.modules_dir):
            module_path = os.path.join(self.modules_dir, module_name)
            if os.path.isdir(module_path):
                module = self._load_module(module_path)
                if module:
                    modules[module_path.split("/")[-1]] = module
        return modules
    
    def load_specific_modules(self, module_names: List[str]) -> List[IModule]:
        """Load specific modules by name"""
        modules = {}
        for module_name in module_names:
            module_path = os.path.join(self.modules_dir, module_name)
            if os.path.isdir(module_path):
                module = self._load_module(module_path)
                if module:
                    modules[module_path.split("/")[-1]] = module
        return modules

    def _load_module(self, module_path: str) -> IModule:
        """Load single module from path"""
        try:
            module_file = os.path.join(module_path, "module.py")
            if not os.path.exists(module_file):
                return None

            spec = importlib.util.spec_from_file_location("module", module_file)
            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find module class that implements IModule
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, IModule) and attr != IModule:
                    return attr()

            return None
        except Exception as e:
            print(f"Error loading module {module_path}: {str(e)}")
            return None