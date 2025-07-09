#!/bin/bash

# Exit on error
set -e

# Generate random passwords if not set
if [ -z "$DB_PASSWORD" ]; then
    export DB_PASSWORD=$(openssl rand -hex 16)
    echo "Generated DB_PASSWORD: $DB_PASSWORD"
fi

if [ -z "$MSF_PASSWORD" ]; then
    export MSF_PASSWORD=$(openssl rand -hex 16)
    echo "Generated MSF_PASSWORD: $MSF_PASSWORD"
fi

if [ -z "$JWT_SECRET" ]; then
    export JWT_SECRET=$(openssl rand -hex 32)
    echo "Generated JWT_SECRET: $JWT_SECRET"
fi

# Create .env file
cat > .env << EOL
DB_PASSWORD=$DB_PASSWORD
MSF_PASSWORD=$MSF_PASSWORD
JWT_SECRET=$JWT_SECRET
EOL

# Build and start services
docker-compose -f deployment/docker-compose.yml build
docker-compose -f deployment/docker-compose.yml up -d

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 10

# Create initial admin user
docker-compose -f deployment/docker-compose.yml exec darkpen python -m darkpen.cli create-admin

echo "Deployment complete! Access the application at http://localhost:8080" 