#!/bin/bash

# Check if a container named 'hol-xpa2023-cloud' already exists
echo "Checking if a container named 'hol-xpa2023-cloud' already exists..."
container_id=$(sudo docker ps -a -q -f name=hol-xpa2023-cloud)

if [ -n "$container_id" ]; then
	# Stop the container
	echo "Stopping container $container_id..."
	sudo docker stop "$container_id"
	echo "Done!"

	# Remove the container
	echo "Removing container $container_id..."
	sudo docker rm "$container_id"
	echo "Done!"
fi

# Pull the latest changes
echo "Pulling the latest changes from the main branch..."
git pull origin main

# Build the Docker image
echo "Building the Docker image..."
sudo docker build -t hol-xpa2023-cloud .

# Run the Docker container
echo "Running the Docker container..."
sudo docker run -d --restart unless-stopped --name hol-xpa2023-cloud-container -p 8000:8000 hol-xpa2023-cloud
