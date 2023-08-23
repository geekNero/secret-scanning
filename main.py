import subprocess

a = subprocess.run(['ls'], capture_output=True)
print(a.stdout)
