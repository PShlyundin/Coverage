import os
from typing import List, Dict, Any
from jinja2 import Environment, FileSystemLoader

class ReportBuilder:
    """Report builder"""
    def __init__(self, output_path: str):
        self.output_path = output_path
        # Get absolute path to modules directory
        modules_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'modules'))
        self.env = Environment(loader=FileSystemLoader(modules_dir))
    
    def build_report(self, results: List[Dict[str, Any]]) -> None:
        """Build final report from module results"""
        with open(self.output_path, 'w') as f:
            for result in results:
                if 'template' in result and 'module_name' in result:
                    # Construct path to module-specific template
                    template_path = os.path.join(result['module_name'], result['template'])
                    template = self.env.get_template(template_path)
                    f.write(template.render(**result))
                    f.write('\n\n') 