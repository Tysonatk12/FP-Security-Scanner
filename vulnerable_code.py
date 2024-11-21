import os

def dangerous_function(user_input):
    # Vulnerable code using eval
    eval(user_input)

def unvalidated_input():
    # Vulnerable code with unvalidated input
    user_data = input("Enter your data: ")
    os.system(f"echo {user_data}")

def zero_division_example():
    # Potential zero-division vulnerability
    divisor = 0
    result = 100 // divisor  # This will throw a ZeroDivisionError
    return result

try:
    unvalidated_input()
except:
    pass
