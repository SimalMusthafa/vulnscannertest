# huge_vulnerable_app.py

import os
import sys
import pickle
from hashlib import md5, sha1
from random import randint, random, choice
from math import *
import sqlite3

DB_PASSWORD = "hard2guess"  # Hardcoded credential

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password  # This should not be stored in plaintext!

    def set_password(self, new_pass):
        # Hardcoded password pattern for demo
        if new_pass == "changeme":
            self.password = new_pass

def user_lookup(user_id):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    # SQL Injection!
    query = "SELECT * FROM users WHERE id=" + user_id
    cur.execute(query)
    user = cur.fetchone()
    conn.close()
    return user

def exec_shell_command(cmd):
    # Command Injection!
    os.system("echo Running: " + cmd)
    os.system(cmd)  # Even worse

def insecure_hash(data):
    # Weak cryptography
    h1 = md5(data.encode()).hexdigest()
    h2 = sha1(data.encode()).hexdigest()
    return h1 + h2

def get_session_token():
    # Insecure random for session token
    token = ""
    for i in range(8):
        token += str(randint(0, 9))
    if random() > 0.5:
        token += str(choice(['A', 'B', 'C']))
    return token

def insecure_eval(expression):
    # Use of eval
    try:
        return eval(expression)
    except Exception as e:
        return str(e)

def bad_pickle_load(serialized):
    # Insecure deserialization
    return pickle.loads(serialized)

def dangerous_open(filename):
    # Path traversal risk
    with open(filename, "r") as f:
        return f.read()

def wildcard_usage():
    # Wildcard import in effect from math import *
    print(sin(0.2) + cos(0.3))

def bad_logging(user_input):
    # Format string vulnerability
    print("User input: " + user_input)
    print("User input (formatted): %s" % user_input)
    print("User input (danger!): " + user_input % ())

def very_bad_admin_login():
    # Super-vulnerable admin check
    admin_password = "admin123"  # Hardcoded
    inp = input("Admin password: ")
    if inp == admin_password:
        print("Welcome, admin!")
    else:
        print("Access denied.")

def main_menu():
    while True:
        print("\nMenu:")
        print("1. Lookup User")
        print("2. Execute Shell Command")
        print("3. Insecure Eval")
        print("4. Insecure Deserialization")
        print("5. Weak Hash")
        print("6. Insecure Token")
        print("7. Wildcard Math")
        print("8. Path Traversal")
        print("9. Bad Logging")
        print("10. Admin Login")
        print("0. Exit")
        choice_input = input("Choice: ")
        if choice_input == "1":
            uid = input("User ID: ")
            print(user_lookup(uid))
        elif choice_input == "2":
            cmd = input("Shell command: ")
            exec_shell_command(cmd)
        elif choice_input == "3":
            exp = input("Python expression: ")
            print(insecure_eval(exp))
        elif choice_input == "4":
            s = input("Paste pickled object: ").encode("latin1")
            try:
                print(bad_pickle_load(s))
            except Exception as e:
                print("Deserialization failed:", e)
        elif choice_input == "5":
            d = input("Data: ")
            print(insecure_hash(d))
        elif choice_input == "6":
            print("Session token:", get_session_token())
        elif choice_input == "7":
            wildcard_usage()
        elif choice_input == "8":
            fn = input("Filename to read: ")
            print(dangerous_open(fn))
        elif choice_input == "9":
            user_input = input("Enter something: ")
            bad_logging(user_input)
        elif choice_input == "10":
            very_bad_admin_login()
        elif choice_input == "0":
            print("Goodbye!")
            break
        else:
            print("Unknown option.")

if __name__ == "__main__":
    print("Welcome to SUPER INSECURE USER MANAGEMENT SYSTEM!")
    main_menu()
