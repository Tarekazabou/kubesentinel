#!/bin/bash
# Local development setup for KubeSentinel with port forwarding

set -e

echo "🔧 Setting up KubeSentinel local development environment..."

# Kill any process using port 8080 (Prometheus metrics)
echo "Checking for processes using port 8080..."
if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    echo "⚠️  Port 8080 is in use. Killing process..."
    fuser -k 8080/tcp || true
    sleep 1
else
    echo "✓ Port 8080 is free"
fi

# Kill any process using port 5000 (AI service)
echo "Checking for processes using port 5000..."
if lsof -Pi :5000 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    echo "⚠️  Port 5000 is in use. Killing process..."
    fuser -k 5000/tcp || true
    sleep 1
else
    echo "✓ Port 5000 is free"
fi

echo ""
echo "🔗 Setting up Kubernetes port forwarding..."

# Port-forward AI service
echo "Forwarding kubesentinel-ai service to localhost:5000..."
kubectl port-forward svc/kubesentinel-ai -n kubesentinel 5000:5000 > /tmp/ai-portforward.log 2>&1 &
AI_PF_PID=$!
echo "✓ Port-forward started (PID: $AI_PF_PID)"

# Port-forward Prometheus metrics (optional)
echo "Forwarding kubesentinel metrics to localhost:8080..."
kubectl port-forward svc/kubesentinel -n kubesentinel 8080:8080 > /tmp/metrics-portforward.log 2>&1 &
METRICS_PF_PID=$!
echo "✓ Port-forward started (PID: $METRICS_PF_PID)"

echo ""
echo "✅ Setup complete!"
echo ""
echo "Available endpoints:"
echo "  • AI Service: http://localhost:5000"
echo "  • Metrics: http://localhost:8080/metrics"
echo ""
echo "To check AI service health:"
echo "  curl http://localhost:5000/health"
echo ""
echo "To stop port forwarding:"
echo "  kill $AI_PF_PID $METRICS_PF_PID"
echo ""
