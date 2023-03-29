import subprocess

# Define a list of commands to run
commands = ["pip install streamlit", "streamlit run contentctl_gui.py"]

# Loop through the list and run each command
for cmd in commands:
    output = subprocess.check_output(cmd, shell=True)
    print(output.decode('utf-8'))
# Print the output
print(output.decode('utf-8'))
 