"""
Config Commands Handler.
"""
from src.repl.dispatcher import dispatcher

def handle_config_command(args, session):
    pass

dispatcher.register("config", handle_config_command)
