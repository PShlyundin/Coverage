from abc import ABC, abstractmethod
from typing import Any, Dict, List
from core.domain_state import DomainState

class IParser(ABC):
    @abstractmethod
    def validate_format(self) -> bool:
        """Validate the format of the input file"""
        pass
    
    @abstractmethod
    def parse(self, domain_state: DomainState) -> None:
        """Parse the input file and update domain state"""
        pass

class IModule(ABC):
    @abstractmethod
    def run(self, domain_state: DomainState) -> None:
        """Run the module and update domain state"""
        pass
    
    @property
    @abstractmethod
    def template_path(self) -> str:
        """Path to report template"""
        pass 

    @classmethod
    def module_name(cls) -> str:
        """Name of the module"""
        return cls.__file__