
#!/bin/bash
set -e
BUILD_DIR="${EVILGINX_SRC:-$HOME/Evilginx3}"
cd "$BUILD_DIR"
echo "Building from $(pwd)..."
CGO_ENABLED=1 go build -mod=vendor -o build/evilginx main.go
sudo cp build/evilginx /opt/evilginx/evilginx.bin
echo "Done. Run 'evilginx-console' to start."