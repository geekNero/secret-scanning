#!/bin/bash

# Access the "exclusions" input parameter
exclusions=$INPUT_EXCLUSIONS

# Split the comma-separated string into an array
IFS=',' read -ra exclusion_array <<< "$exclusions"

# Loop through the array and process each exclusion
for exclusion in "${exclusion_array[@]}"; do
  echo "Excluding: $exclusion"
  # Your action's exclusion logic here
done

# Your action's main logic here
