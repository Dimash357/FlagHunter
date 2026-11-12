# Deliberately vulnerable-looking snippets for static detection only.
import os

def suspicious(user_input):
    os.system(user_input)
    return f"SELECT * FROM users WHERE name = '{user_input}'"
