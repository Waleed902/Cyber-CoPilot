"""
Scan Commands Handler.
"""
from src.repl.dispatcher import dispatcher

def handle_scan_command(args, session):
    pass

dispatcher.register("scan", handle_scan_command)
