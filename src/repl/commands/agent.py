"""
Agent Commands Handler.
"""
from src.repl.dispatcher import dispatcher

def handle_agent_command(args, session):
    pass

dispatcher.register("agent", handle_agent_command)
