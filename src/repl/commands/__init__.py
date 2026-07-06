"""
Registers all REPL slash commands to the dispatcher.
"""
import os
import glob
import importlib

# Automatically import all command handlers in this directory
modules = glob.glob(os.path.join(os.path.dirname(__file__), "*.py"))
__all__ = [os.path.basename(f)[:-3] for f in modules if os.path.isfile(f) and not f.endswith('__init__.py')]

# You can register commands globally via the dispatcher instance
from src.repl.dispatcher import dispatcher

# Example hook point where we'd bind everything
def load_commands():
    # Will import .graph, .scan, etc.
    for module_name in __all__:
        if module_name != "dispatcher" and module_name != "session":
            importlib.import_module(f"src.repl.commands.{module_name}")
