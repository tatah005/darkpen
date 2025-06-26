FROM kalilinux/kali-rolling

# Update and install required packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    nmap \
    nikto \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data/backups logs

# Set environment variables
ENV PYTHONPATH=/app
ENV DARKPEN_ENV=production

# Expose port
EXPOSE 8080

# Run the application
CMD ["python3", "-m", "darkpen.main"] 