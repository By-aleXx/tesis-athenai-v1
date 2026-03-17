#!/bin/bash
# Setup script for Nginx WAF

echo "🚀 Setting up Nginx WAF for AthenAI..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p nginx/ssl
mkdir -p nginx/conf.d
mkdir -p nginx/modsecurity/rules
mkdir -p nginx/sites-available
mkdir -p nginx/sites-enabled
mkdir -p logs/nginx
mkdir -p logs/modsecurity

echo "✅ Directories created"

# Generate SSL certificate if not exists
if [ ! -f "nginx/ssl/athenai.crt" ]; then
    echo "🔐 Generating self-signed SSL certificate..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/athenai.key \
        -out nginx/ssl/athenai.crt \
        -subj "/C=US/ST=State/L=City/O=AthenAI/CN=localhost"
    
    chmod 600 nginx/ssl/athenai.key
    chmod 644 nginx/ssl/athenai.crt
    echo "✅ SSL certificate generated"
else
    echo "✅ SSL certificate already exists"
fi

# Build Docker image
echo "🐳 Building Nginx Docker image..."
docker build -f Dockerfile.nginx -t athenai-nginx:latest .

if [ $? -eq 0 ]; then
    echo "✅ Docker image built successfully"
else
    echo "❌ Failed to build Docker image"
    exit 1
fi

# Start services
echo "🚀 Starting Nginx WAF..."
docker-compose -f docker-compose.nginx.yml up -d

if [ $? -eq 0 ]; then
    echo "✅ Nginx WAF started successfully"
else
    echo "❌ Failed to start Nginx WAF"
    exit 1
fi

# Wait for Nginx to start
echo "⏳ Waiting for Nginx to start..."
sleep 5

# Test Nginx
echo "🧪 Testing Nginx..."
curl -k https://localhost/api/health > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✅ Nginx is responding"
else
    echo "⚠️  Nginx is not responding yet. Check logs with: docker-compose -f docker-compose.nginx.yml logs nginx"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "📊 Access AthenAI:"
echo "   HTTP:  http://localhost"
echo "   HTTPS: https://localhost"
echo ""
echo "📝 View logs:"
echo "   docker-compose -f docker-compose.nginx.yml logs -f nginx"
echo ""
echo "🛑 Stop services:"
echo "   docker-compose -f docker-compose.nginx.yml down"
