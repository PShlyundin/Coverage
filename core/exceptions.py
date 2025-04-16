class ParserError(Exception):
    """Base exception for parser errors"""
    pass

class ValidationError(ParserError):
    """Exception for validation errors"""
    pass

class ModuleError(Exception):
    """Base exception for module errors"""
    pass

class ModuleLoadError(ModuleError):
    """Exception for module loading errors"""
    pass

class ModuleExecutionError(ModuleError):
    """Exception for module execution errors"""
    pass

class ReportError(Exception):
    """Base exception for report errors"""
    pass 