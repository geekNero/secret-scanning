import json
from tabulate import tabulate

# Read JSON data from file
with open('data.json') as f:
    data = json.load(f)

# Extract relevant fields and create a list of rows
table_data = [[entry['name'], entry['description']] for entry in data]

# Define column headers
headers = ['Name', 'Description']

# Create the tabular representation
table = tabulate(table_data, headers=headers, tablefmt='grid')

# Print the tabular data
print(table)