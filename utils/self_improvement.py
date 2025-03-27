"""
Self-Improvement Module

This module provides autonomous self-improvement capabilities for the AI system,
allowing it to optimize its own code, learn from execution patterns, and evolve
over time through multiple generations.
"""

import ast
import inspect
import logging
import os
import re
import time
import traceback
import importlib
from datetime import datetime
import threading
import hashlib

# Configure logging
logger = logging.getLogger(__name__)

# Global registry of improvements
code_improvements = []
performance_metrics = {}
optimization_targets = {}
code_generation_history = []

# Lock for thread-safe operations
improvement_lock = threading.Lock()


class CodeAnalyzer:
    """Analyze code structure and identify optimization opportunities"""
    
    def __init__(self):
        self.analyzed_files = set()
        self.complexity_scores = {}
        self.dependency_graph = {}
        self.bottlenecks = []
        
    def analyze_file(self, filepath):
        """
        Analyze a Python file to identify optimization opportunities
        
        Args:
            filepath: Path to the Python file
            
        Returns:
            dict: Analysis results with optimization suggestions
        """
        if not os.path.exists(filepath) or not filepath.endswith('.py'):
            return {"error": f"Invalid file path: {filepath}"}
            
        if filepath in self.analyzed_files:
            return {"status": "already_analyzed", "file": filepath}
            
        try:
            with open(filepath, 'r') as f:
                code = f.read()
                
            # Parse the code
            tree = ast.parse(code)
            
            # Analyze complexity
            complexity_visitor = ComplexityVisitor()
            complexity_visitor.visit(tree)
            complexity = complexity_visitor.complexity
            
            # Analyze function lengths
            function_lengths = {}
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    function_lengths[node.name] = node.end_lineno - node.lineno if hasattr(node, 'end_lineno') else 0
            
            # Find imports and dependencies
            imports = self._extract_imports(tree)
            
            # Store results
            self.complexity_scores[filepath] = complexity
            self.analyzed_files.add(filepath)
            
            # Identify potential issues
            issues = []
            
            # High complexity functions
            for name, score in complexity_visitor.function_complexity.items():
                if score > 10:  # McCabe complexity threshold
                    issues.append({
                        "type": "high_complexity",
                        "function": name,
                        "score": score,
                        "suggestion": "Consider refactoring this function into smaller, more focused functions."
                    })
            
            # Long functions
            for name, length in function_lengths.items():
                if length > 50:  # Line count threshold
                    issues.append({
                        "type": "long_function",
                        "function": name,
                        "lines": length,
                        "suggestion": "Consider breaking this function into smaller, more maintainable pieces."
                    })
            
            # Detect potential performance issues
            performance_issues = self._detect_performance_issues(code)
            issues.extend(performance_issues)
            
            return {
                "file": filepath,
                "complexity": complexity,
                "imports": imports,
                "function_count": len(function_lengths),
                "total_lines": sum(function_lengths.values()),
                "issues": issues,
                "optimization_potential": "high" if len(issues) > 3 else "medium" if len(issues) > 0 else "low"
            }
            
        except Exception as e:
            logger.error(f"Error analyzing file {filepath}: {str(e)}")
            return {"error": str(e), "file": filepath}
    
    def _extract_imports(self, tree):
        """Extract import statements from AST"""
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.append(name.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                for name in node.names:
                    imports.append(f"{module}.{name.name}")
        return imports
        
    def _detect_performance_issues(self, code):
        """Detect potential performance issues in code"""
        issues = []
        
        # Check for inefficient list operations
        if re.search(r'for\s+\w+\s+in\s+\w+\s*:\s*\w+\.append', code):
            issues.append({
                "type": "inefficient_list_building",
                "suggestion": "Consider using list comprehension instead of for-loop with append()."
            })
        
        # Check for repeated string concatenation
        if re.search(r'\w+\s*\+=\s*[\'"]\w+[\'"]', code):
            issues.append({
                "type": "string_concatenation",
                "suggestion": "Consider using join() or string formatting instead of repeated += for strings."
            })
        
        # Check for inefficient dictionary access in loops
        if re.search(r'for\s+\w+\s+in\s+\w+\s*:.*\w+\[\w+\]', code):
            issues.append({
                "type": "dict_lookups_in_loop",
                "suggestion": "Consider using dict.get() with default or checking for key existence before loop."
            })
            
        return issues
        
    def find_optimization_targets(self, directory='.', exclude_dirs=None):
        """
        Scan a directory for Python files to find optimization targets
        
        Args:
            directory: Root directory to scan
            exclude_dirs: List of directories to exclude
            
        Returns:
            list: Files ranked by optimization potential
        """
        if exclude_dirs is None:
            exclude_dirs = ['venv', 'env', '__pycache__', '.git']
            
        targets = []
        
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    analysis = self.analyze_file(filepath)
                    if 'error' not in analysis and 'issues' in analysis and len(analysis['issues']) > 0:
                        targets.append({
                            'file': filepath,
                            'issues': len(analysis['issues']),
                            'complexity': analysis.get('complexity', 0),
                            'optimization_potential': analysis.get('optimization_potential', 'low')
                        })
        
        # Sort by optimization potential
        targets.sort(key=lambda x: (
            0 if x['optimization_potential'] == 'high' else 
            1 if x['optimization_potential'] == 'medium' else 2,
            -x['issues'],
            -x['complexity']
        ))
        
        return targets


class ComplexityVisitor(ast.NodeVisitor):
    """AST visitor to calculate cyclomatic complexity"""
    
    def __init__(self):
        self.complexity = 0
        self.function_complexity = {}
        self.current_function = None
        
    def visit_FunctionDef(self, node):
        old_function = self.current_function
        self.current_function = node.name
        self.function_complexity[node.name] = 1  # Base complexity
        
        # Visit all children
        self.generic_visit(node)
        
        self.current_function = old_function
        
    def visit_If(self, node):
        self._increment_complexity()
        self.generic_visit(node)
        
    def visit_IfExp(self, node):
        self._increment_complexity()
        self.generic_visit(node)
        
    def visit_For(self, node):
        self._increment_complexity()
        self.generic_visit(node)
        
    def visit_While(self, node):
        self._increment_complexity()
        self.generic_visit(node)
        
    def visit_Try(self, node):
        self._increment_complexity()
        self.generic_visit(node)
        
    def visit_ExceptHandler(self, node):
        self._increment_complexity()
        self.generic_visit(node)
        
    def visit_With(self, node):
        self._increment_complexity()
        self.generic_visit(node)
        
    def visit_AsyncWith(self, node):
        self._increment_complexity()
        self.generic_visit(node)
        
    def visit_BoolOp(self, node):
        self._increment_complexity(len(node.values) - 1)
        self.generic_visit(node)
        
    def _increment_complexity(self, amount=1):
        self.complexity += amount
        if self.current_function:
            self.function_complexity[self.current_function] = self.function_complexity.get(self.current_function, 0) + amount


class CodeImprover:
    """Generate improved versions of code"""
    
    def __init__(self, app=None):
        self.app = app
        self.analyzer = CodeAnalyzer()
        
    def improve_file(self, filepath, improvement_type="optimization"):
        """
        Attempt to improve a Python file
        
        Args:
            filepath: Path to the Python file
            improvement_type: Type of improvement to make (optimization, readability, bugfix)
            
        Returns:
            dict: Improvement details including suggested changes
        """
        logger.info(f"Attempting to improve file: {filepath} (type: {improvement_type})")
        
        try:
            # First analyze the file
            analysis = self.analyzer.analyze_file(filepath)
            
            if 'error' in analysis:
                return {"error": analysis['error'], "file": filepath}
                
            # Read the file content
            with open(filepath, 'r') as f:
                original_code = f.read()
                
            # Select improvement strategy based on type and analysis
            improvement_function = self._select_improvement_strategy(improvement_type, analysis)
            
            # Generate improved code
            improved_code, changes = improvement_function(original_code, analysis)
            
            if improved_code == original_code:
                return {
                    "status": "no_changes",
                    "file": filepath,
                    "message": "No improvements identified for this file"
                }
                
            # Calculate improvement statistics
            improvement_stats = self._calculate_improvement_stats(original_code, improved_code)
            
            # Generate diff
            diff = self._generate_diff(original_code, improved_code)
            
            # Log the improvement
            improvement_id = hashlib.md5((filepath + str(time.time())).encode()).hexdigest()
            
            improvement = {
                "id": improvement_id,
                "file": filepath,
                "type": improvement_type,
                "timestamp": datetime.utcnow().isoformat(),
                "changes": changes,
                "diff": diff,
                "stats": improvement_stats,
                "improved_code": improved_code,
                "original_code": original_code,
                "status": "proposed"
            }
            
            # Store in database if app context is available
            if self.app:
                with self.app.app_context():
                    from models import CodeImprovement, db
                    code_imp = CodeImprovement(
                        file_path=filepath,
                        description=", ".join(c['description'] for c in changes),
                        diff=diff,
                        improvement_type=improvement_type,
                        status="proposed",
                        created_at=datetime.utcnow()
                    )
                    db.session.add(code_imp)
                    db.session.commit()
                    improvement["db_id"] = code_imp.id
            
            # Add to global registry
            with improvement_lock:
                code_improvements.append(improvement)
            
            return {
                "status": "success",
                "file": filepath,
                "improvement_id": improvement_id,
                "changes": changes,
                "stats": improvement_stats
            }
            
        except Exception as e:
            logger.error(f"Error improving file {filepath}: {str(e)}")
            logger.error(traceback.format_exc())
            return {"error": str(e), "file": filepath}
    
    def _select_improvement_strategy(self, improvement_type, analysis):
        """Select the appropriate improvement strategy based on type and analysis"""
        if improvement_type == "optimization":
            # Choose specific optimization based on analysis
            if any(issue['type'] == 'inefficient_list_building' for issue in analysis.get('issues', [])):
                return self._optimize_list_operations
            elif any(issue['type'] == 'string_concatenation' for issue in analysis.get('issues', [])):
                return self._optimize_string_operations
            elif any(issue['type'] == 'dict_lookups_in_loop' for issue in analysis.get('issues', [])):
                return self._optimize_dict_lookups
            else:
                return self._general_optimization
        elif improvement_type == "readability":
            return self._improve_readability
        elif improvement_type == "bugfix":
            return self._fix_common_bugs
        else:
            return self._general_optimization
            
    def _general_optimization(self, code, analysis):
        """General code optimization strategy"""
        changes = []
        improved_code = code
        
        # Look for high complexity functions to refactor
        complex_funcs = [i for i in analysis.get('issues', []) if i['type'] == 'high_complexity']
        if complex_funcs:
            # This is a placeholder - in a real system we would use a more sophisticated 
            # approach involving actual code refactoring using AST manipulation
            changes.append({
                "type": "refactor_suggestion",
                "description": f"Refactor complex function: {complex_funcs[0]['function']}",
                "detail": complex_funcs[0]['suggestion']
            })
        
        # Look for inefficient patterns and replace them
        patterns = [
            # Replace list appends in loops with list comprehension
            (
                r'(\w+)\s*=\s*\[\]\s*\n\s*for\s+(\w+)\s+in\s+(\w+)\s*:\s*\n\s*\1\.append\((\w+)\)',
                lambda m: f"{m.group(1)} = [{m.group(4)} for {m.group(2)} in {m.group(3)}]",
                "Convert append in loop to list comprehension"
            ),
            # Replace nested loops with more efficient operations
            (
                r'for\s+(\w+)\s+in\s+(\w+)\s*:\s*\n\s*for\s+(\w+)\s+in\s+(\w+)\s*:',
                lambda m: f"# Consider using itertools.product\nfor {m.group(1)}, {m.group(3)} in itertools.product({m.group(2)}, {m.group(4)}):",
                "Suggest itertools.product for nested loops"
            )
        ]
        
        for pattern, replacement, description in patterns:
            new_code = re.sub(pattern, replacement, improved_code)
            if new_code != improved_code:
                improved_code = new_code
                changes.append({
                    "type": "optimization",
                    "description": description
                })
                
        return improved_code, changes
        
    def _optimize_list_operations(self, code, analysis):
        """Optimize list operations"""
        changes = []
        
        # Replace list building with append in loops with list comprehensions
        pattern = r'(\w+)\s*=\s*\[\]\s*\n\s*for\s+(\w+)\s+in\s+(\w+)\s*:\s*\n\s*\1\.append\((.+?)\)'
        new_code = re.sub(pattern, lambda m: f"{m.group(1)} = [{m.group(4)} for {m.group(2)} in {m.group(3)}]", code)
        
        if new_code != code:
            changes.append({
                "type": "optimization",
                "description": "Convert append in loop to list comprehension"
            })
            code = new_code
            
        return code, changes
        
    def _optimize_string_operations(self, code, analysis):
        """Optimize string operations"""
        changes = []
        
        # Replace string concatenation in loops with join
        pattern = r'(\w+)\s*=\s*[\'\"](.*?)[\'\"]\s*\n\s*for\s+(\w+)\s+in\s+(\w+)\s*:\s*\n\s*\1\s*\+=\s*(.+)'
        
        new_code = re.sub(pattern, 
                         lambda m: f"{m.group(1)}_parts = []\n    for {m.group(3)} in {m.group(4)}:\n        " +
                                  f"{m.group(1)}_parts.append(str({m.group(5)}))\n    {m.group(1)} = \"{m.group(2)}\".join({m.group(1)}_parts)",
                         code)
        
        if new_code != code:
            changes.append({
                "type": "optimization",
                "description": "Convert string concatenation to join method"
            })
            code = new_code
            
        return code, changes
        
    def _optimize_dict_lookups(self, code, analysis):
        """Optimize dictionary lookups"""
        changes = []
        
        # Replace repeated dict lookups with variable assignment
        pattern = r'for\s+(\w+)\s+in\s+(\w+)\s*:\s*\n((\s+.*?\n)*?\s+.*?)(\w+)\[(\w+)\](.*?\n)((\s+.*?\n)*?\s+.*?)(\w+)\[(\w+)\]'
        
        def replace_repeated_lookup(match):
            # If the same dictionary and key are used multiple times
            if match.group(5) == match.group(9) and match.group(6) == match.group(10):
                indent = re.search(r'^(\s+)', match.group(3)).group(1) if re.search(r'^(\s+)', match.group(3)) else '    '
                return f"for {match.group(1)} in {match.group(2)}:\n{indent}{match.group(5)}_value = {match.group(5)}[{match.group(6)}]\n{match.group(3)}{match.group(5)}_value{match.group(7)}{match.group(8)}{match.group(5)}_value"
            return match.group(0)
            
        new_code = re.sub(pattern, replace_repeated_lookup, code)
        
        if new_code != code:
            changes.append({
                "type": "optimization",
                "description": "Cache dictionary lookup in loop"
            })
            code = new_code
        
        return code, changes
        
    def _improve_readability(self, code, analysis):
        """Improve code readability"""
        changes = []
        
        # Add docstrings to functions that don't have them
        tree = ast.parse(code)
        missing_docstrings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if (not node.body or not isinstance(node.body[0], ast.Expr) or 
                    not isinstance(node.body[0].value, ast.Str)):
                    missing_docstrings.append(node.name)
        
        if missing_docstrings:
            changes.append({
                "type": "readability",
                "description": f"Add docstrings to functions: {', '.join(missing_docstrings)}"
            })
            
            # This is a placeholder - in a real system we would use AST manipulation
            # to properly add docstrings to the functions
            
        # Improve variable names (placeholder - would need more sophisticated analysis)
        short_var_pattern = r'\bfor\s+([a-z])\s+in\b'
        new_code = re.sub(short_var_pattern, 
                         lambda m: f"for item_{m.group(1)} in" if len(m.group(1)) == 1 else m.group(0),
                         code)
        
        if new_code != code:
            changes.append({
                "type": "readability",
                "description": "Improve variable naming in loops"
            })
            code = new_code
        
        return code, changes
        
    def _fix_common_bugs(self, code, analysis):
        """Fix common bugs and issues"""
        changes = []
        
        # Fix bare excepts
        bare_except_pattern = r'except\s*:'
        new_code = re.sub(bare_except_pattern, 'except Exception:', code)
        
        if new_code != code:
            changes.append({
                "type": "bugfix",
                "description": "Replace bare except with except Exception"
            })
            code = new_code
            
        # Fix mutable default arguments
        mutable_default_pattern = r'def\s+(\w+)\s*\((.*?)(\[\s*\]|\{\s*\}|\(\s*\))(\s*=\s*)(.*?)\)'
        new_code = re.sub(mutable_default_pattern, 
                         lambda m: f"def {m.group(1)}({m.group(2)}None{m.group(4)}{m.group(5)}):\n    {m.group(2)} = {m.group(3)} if {m.group(2)} is None else {m.group(2)}",
                         code)
        
        if new_code != code:
            changes.append({
                "type": "bugfix",
                "description": "Fix mutable default argument"
            })
            code = new_code
        
        return code, changes
        
    def _calculate_improvement_stats(self, original_code, improved_code):
        """Calculate statistics about the improvement"""
        original_lines = original_code.count('\n') + 1
        improved_lines = improved_code.count('\n') + 1
        
        # Estimate performance improvement (placeholder - would need real benchmarking)
        performance_estimate = "Unknown"
        if original_lines > improved_lines:
            performance_estimate = "Potentially improved (code is more concise)"
        elif original_lines < improved_lines:
            performance_estimate = "Potentially reduced (code is more verbose but may be clearer)"
        
        return {
            "original_lines": original_lines,
            "improved_lines": improved_lines,
            "line_diff": improved_lines - original_lines,
            "performance_estimate": performance_estimate
        }
        
    def _generate_diff(self, original_code, improved_code):
        """Generate a simple diff representation"""
        import difflib
        
        original_lines = original_code.splitlines()
        improved_lines = improved_code.splitlines()
        
        diff = list(difflib.unified_diff(
            original_lines, improved_lines,
            fromfile='original',
            tofile='improved',
            lineterm='',
            n=3
        ))
        
        return '\n'.join(diff)
        
    def apply_improvement(self, improvement_id, db_session=None):
        """
        Apply a proposed code improvement
        
        Args:
            improvement_id: ID of the improvement to apply
            db_session: Database session for updating status
            
        Returns:
            bool: True if successfully applied
        """
        # Find the improvement
        improvement = None
        with improvement_lock:
            for imp in code_improvements:
                if imp['id'] == improvement_id:
                    improvement = imp
                    break
        
        if not improvement:
            logger.error(f"Improvement {improvement_id} not found")
            return False
            
        try:
            # Write the improved code to the file
            with open(improvement['file'], 'w') as f:
                f.write(improvement['improved_code'])
                
            # Update status
            improvement['status'] = "implemented"
            improvement['implemented_at'] = datetime.utcnow().isoformat()
            
            # Update database record if available
            if db_session and 'db_id' in improvement:
                from models import CodeImprovement
                db_improvement = db_session.query(CodeImprovement).get(improvement['db_id'])
                if db_improvement:
                    db_improvement.status = "implemented"
                    db_improvement.implemented_at = datetime.utcnow()
                    db_session.commit()
            
            logger.info(f"Successfully applied improvement {improvement_id} to {improvement['file']}")
            return True
            
        except Exception as e:
            logger.error(f"Error applying improvement {improvement_id}: {str(e)}")
            return False


class SelfImprovement:
    """Main interface for the self-improvement module"""
    
    def __init__(self, app=None):
        self.app = app
        self.analyzer = CodeAnalyzer()
        self.improver = CodeImprover(app)
        self.learning_targets = []
        self.improvement_queue = []
        self.is_improvement_running = False
        
    def scan_for_improvements(self, directory='.', exclude_dirs=None):
        """
        Scan codebase for potential improvements
        
        Args:
            directory: Root directory to scan
            exclude_dirs: Directories to exclude
            
        Returns:
            list: Ranked improvement targets
        """
        logger.info(f"Scanning for improvement targets in {directory}")
        
        if exclude_dirs is None:
            exclude_dirs = ['venv', 'env', '__pycache__', '.git']
            
        targets = self.analyzer.find_optimization_targets(directory, exclude_dirs)
        
        logger.info(f"Found {len(targets)} potential improvement targets")
        self.improvement_queue = targets[:10]  # Take top 10 targets
        
        return targets
        
    def run_improvement_cycle(self, max_improvements=3):
        """
        Run a cycle of code improvements
        
        Args:
            max_improvements: Maximum number of improvements to make in this cycle
            
        Returns:
            list: Details of improvements made
        """
        if self.is_improvement_running:
            return {"status": "already_running", "message": "Improvement cycle already in progress"}
            
        self.is_improvement_running = True
        improvements_made = []
        
        try:
            logger.info(f"Starting improvement cycle (max: {max_improvements})")
            
            # Scan for targets if queue is empty
            if not self.improvement_queue:
                self.scan_for_improvements()
                
            # Process the queue
            for _ in range(min(max_improvements, len(self.improvement_queue))):
                if not self.improvement_queue:
                    break
                    
                target = self.improvement_queue.pop(0)
                logger.info(f"Attempting to improve {target['file']}")
                
                # Attempt the improvement
                result = self.improver.improve_file(target['file'])
                
                if result.get('status') == 'success':
                    improvements_made.append(result)
                    logger.info(f"Successfully improved {target['file']}")
                    
                    # Apply the improvement if we have app context
                    if self.app and result.get('improvement_id'):
                        with self.app.app_context():
                            from models import db
                            self.improver.apply_improvement(result['improvement_id'], db.session)
                else:
                    logger.warning(f"Failed to improve {target['file']}: {result.get('error', 'Unknown error')}")
            
            logger.info(f"Improvement cycle completed: {len(improvements_made)} improvements made")
            return {
                "status": "completed",
                "improvements_made": len(improvements_made),
                "details": improvements_made
            }
            
        except Exception as e:
            logger.error(f"Error in improvement cycle: {str(e)}")
            logger.error(traceback.format_exc())
            return {"status": "error", "message": str(e)}
            
        finally:
            self.is_improvement_running = False
    
    def monitor_performance(self, function_to_monitor, sample_size=10):
        """
        Monitor the performance of a function
        
        Args:
            function_to_monitor: Function or method to monitor
            sample_size: Number of performance samples to collect
            
        Returns:
            dict: Performance statistics
        """
        if isinstance(function_to_monitor, str):
            # Try to import the function by name
            module_name, function_name = function_to_monitor.rsplit('.', 1)
            try:
                module = importlib.import_module(module_name)
                function_to_monitor = getattr(module, function_name)
            except (ImportError, AttributeError) as e:
                return {"error": f"Could not import function {function_to_monitor}: {str(e)}"}
        
        func_name = function_to_monitor.__qualname__
        module = function_to_monitor.__module__
        
        # Wrap the function to measure performance
        original_function = function_to_monitor
        times = []
        
        def performance_wrapper(*args, **kwargs):
            start_time = time.time()
            result = original_function(*args, **kwargs)
            end_time = time.time()
            times.append(end_time - start_time)
            return result
            
        # Replace the function with our wrapper
        function_to_monitor.__globals__[func_name] = performance_wrapper
        
        # Return a function to complete the monitoring and restore the original
        def get_results():
            # Restore original function
            function_to_monitor.__globals__[func_name] = original_function
            
            if not times:
                return {"status": "no_data", "function": f"{module}.{func_name}"}
                
            avg_time = sum(times) / len(times)
            min_time = min(times)
            max_time = max(times)
            
            results = {
                "function": f"{module}.{func_name}",
                "samples": len(times),
                "avg_time": avg_time,
                "min_time": min_time,
                "max_time": max_time,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Store in performance metrics
            global performance_metrics
            if module not in performance_metrics:
                performance_metrics[module] = {}
            performance_metrics[module][func_name] = results
            
            return results
            
        return get_results


# Create global self-improvement instance
self_improver = None

def initialize_self_improvement(app=None):
    """Initialize the self-improvement module"""
    global self_improver
    self_improver = SelfImprovement(app)
    return self_improver

def get_self_improver():
    """Get the global self-improvement instance"""
    global self_improver
    if self_improver is None:
        self_improver = SelfImprovement()
    return self_improver