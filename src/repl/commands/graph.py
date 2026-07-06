"""
Graph Commands Handler.
"""
from src.repl.dispatcher import dispatcher

def handle_graph_command(args, session):
    pass

dispatcher.register("graph", handle_graph_command)
