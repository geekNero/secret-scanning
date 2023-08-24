import subprocess
import os

a = subprocess.run(['ls'], capture_output=True)
output_path = os.getenv('GITHUB_OUTPUT')
with open(output_path, "a") as myfile:
    myfile.write(a.stdout)
