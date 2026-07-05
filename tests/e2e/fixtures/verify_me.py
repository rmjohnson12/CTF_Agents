import sys

def check_password(password):
    if len(password) != 10:
        return False
    
    # Simple constraints for ReverseEngineeringAgent to find
    builder = 0
    for char in password:
        builder += ord(char)
        
    if builder == 1000:
        if ord(password[1]) == 83: # 'S'
            return True
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_me.py <password>")
        sys.exit(1)
    
    if check_password(sys.argv[1]):
        print("Correct! The flag is: CTF{RE_MASTER_SOLVER}")
    else:
        print("Wrong password.")
