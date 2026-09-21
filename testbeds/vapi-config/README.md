# vAPI testbed setup

vAPI's source is not vendored in this repo (see .gitignore). To reproduce:

```bash
cd testbeds
git clone https://github.com/roottusk/vapi.git vapi
cp vapi-config/docker-compose.yml vapi/docker-compose.yml
cd vapi
docker compose up -d db www
```

The docker-compose.yml here is roottusk/vapi's original file with one
change: all port bindings prefixed with 127.0.0.1: so the deliberately
vulnerable app is not reachable from the network.

phpmyadmin is excluded from the up command; its image has a platform
mismatch on Apple Silicon (exits with code 127) and is not needed for
TRACE's testing.
