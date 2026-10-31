import subprocess
from flask import request

def run_user_expression():
    expression = request.args.get("expr", "")
    return str(eval(expression))
