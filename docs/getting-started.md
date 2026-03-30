# Getting Started with KubeSentinel

This guide helps you install prerequisites, build KubeSentinel, and run your first scan.

## Prerequisites

KubeSentinel requires:

- Go `1.21+`
- Python `3.9+`
- Docker
- Kubernetes CLI (`kubectl`)
- Local Kubernetes runtime (`minikube` or `kind`)
- Falco (required only for runtime monitoring)

## 1) Clone the Repository

```bash
git clone <your-repo-url>
cd kubesentinel
```

## 2) Install Prerequisites

Choose the option for your OS.

### Linux / macOS (Bash installer)

```bash
chmod +x ./scripts/install-prereqs.sh
./scripts/install-prereqs.sh
```

Optional: install Falco too

```bash
./scripts/install-prereqs.sh --with-falco
```

### Windows (PowerShell)

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\install.ps1
```

Notes:
- `make` is optional on Windows. If `make` is unavailable, use direct `go`/`python` commands shown below.
- If Docker was installed during setup, restart your terminal session before using Docker commands.

## 3) Install Project Dependencies

### With Make (Linux/macOS or Windows with Make installed)

```bash
make -f scripts/Makefile deps
```

### Without Make (works everywhere)

```bash
go mod download
go mod tidy
python -m pip install -r requirements.txt
python -m pip install -r ai-module/requirements.txt
```

If `ai-module/requirements.txt` contains unresolved merge conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`), resolve that file first.

## 4) Build KubeSentinel

### With Make

```bash
make -f scripts/Makefile build
```

### Without Make

```bash
go build -o ./bin/kubesentinel ./cmd/kubesentinel
```

## 5) Run Your First Static Scan

```bash
./bin/kubesentinel scan --path ./deploy
```

You should see findings for test manifests in `deploy/`.

## 6) Start AI Service (Optional but Recommended)

```bash
cd ai-module
python server.py
```

Health check:

```bash
curl http://localhost:5000/health
```

## 7) Runtime Monitoring (Requires Falco)

```bash
./bin/kubesentinel monitor --namespace production --deployment api
```

For log pipeline mode:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco -f --all-containers | ./bin/kubesentinel monitor-stdin
```

## 8) Run Tests

### With Make

```bash
make -f scripts/Makefile test
```

### Without Make

```bash
go test -v -race -cover ./...
python -m pytest ai-module/tests/ -v
```

## Common Troubleshooting

### `make` not found

Use direct commands (`go build`, `go test`, `python -m pip ...`) from this guide.

### `falco.sock` not found

Falco is not running or socket path differs from config. Start Falco and verify your runtime socket path.

### Python dependencies fail to install

Upgrade pip and retry:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Docker permission denied (Linux)

Add your user to Docker group and re-login:

```bash
sudo usermod -aG docker $USER
```

## Next Steps

- Review architecture: [architecture.md](architecture.md)
- Quick command reference: [quick-reference.md](quick-reference.md)
- Project walkthrough: [PROJECT-GUIDE.md](PROJECT-GUIDE.md)
