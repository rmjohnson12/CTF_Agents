"""
CTF reverse engineering challenge fixture.
Constraints the agent must discover and solve:
  - len(password) == 8
  - builder (sum of ords) == 776
  - ord(password[2]) == 84  ('T')
Solution: "hbTbbbbb"
"""
import sys

if __name__ == "__main__":
    password = sys.argv[1] if len(sys.argv) > 1 else ""
    builder = sum(ord(c) for c in password)
    if len(password) == 8 and builder == 776 and ord(password[2]) == 84:
        print("correct")
    else:
        print(f"incorrect (sum={builder}, expected 776)")
