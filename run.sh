#!/bin/bash

# Stop any running containers
sudo docker-compose -f deployment/docker-compose.yml down

# Set environment variables
export DB_PASSWORD=darkpen_secure_db_2024
export MSF_PASSWORD=darkpen_secure_msf_2024
export JWT_SECRET=darkpen_secure_jwt_token_2024

# Build and start containers
sudo -E docker-compose -f deployment/docker-compose.yml up --build -d

# Wait for services to start
echo "Starting DarkPen..."
sleep 10

# Show running containers
sudo docker ps

echo -e "\nDarkPen is running!"
echo "Access the application at: http://localhost:8080" 