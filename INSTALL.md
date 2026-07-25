# IAM Sentinel — Installation Manual (Mac · Windows · Linux · WSL)

IAM Sentinel runs anywhere Docker runs. It has two parts:

1. **IAM Sentinel API** — the deterministic auditor. **CPU-only, tiny, runs on every OS.**
2. **Local LLM (Ollama)** — *optional*. Only powers the written remediation *narrative*.
   Needs an NVIDIA GPU (Linux/WSL). On Mac/Windows-without-NVIDIA, simply run
   **deterministic-only mode** — you still get every finding + a fix hint per finding.

> **You do not need a GPU to use IAM Sentinel.** The findings — the product — are deterministic
> and CPU-only. The GPU is a nice-to-have for prose remediation.

---

## 0. Prerequisites (all systems)

- **Docker** with **Docker Compose v2** (`docker compose version` should print v2.x).
- 4 GB RAM free (deterministic-only) / 16 GB+ if you also run a local model.
- A terminal.

Install Docker:
- **Windows / macOS:** install **Docker Desktop** → https://www.docker.com/products/docker-desktop
- **Linux:** install Docker Engine + compose plugin → https://docs.docker.com/engine/install

---

## 1. Unzip

```bash
unzip iam-sentinel-1.0.0.zip && cd iam-sentinel
```
(Windows: right-click → Extract All, then open the folder in a terminal.)

## 2. Configure (30 seconds)

```bash
cp .env.example .env
```
Open `.env` and set at least:
```
AUTH_ENABLED=true
IAM_SENTINEL_API_KEYS=analyst:analyst:PUT_A_LONG_RANDOM_SECRET_HERE,ciso:admin:ANOTHER_SECRET
```
Generate strong secrets:
- macOS/Linux/WSL: `openssl rand -hex 24`
- Windows PowerShell: `-join ((48..57)+(97..102) | Get-Random -Count 48 | %{[char]$_})`

If a vendor gave you a license, also add: `LICENSE_KEY=...` and `LICENSE_PUBLIC_KEY=...`
(No license = free **Community** tier: 1 seat, 100 scans/month.)

---

## 3. Launch — pick your platform

### 🪟 Windows (Docker Desktop)
1. Start Docker Desktop (uses the WSL2 backend).
2. In PowerShell or Windows Terminal, from the unzipped folder:
   ```powershell
   docker compose up -d --build
   ```
3. GPU narrative: Windows + NVIDIA works **through WSL2** (see WSL section). Otherwise use
   **deterministic-only mode** (below).

### 🍎 macOS (Docker Desktop)
1. Start Docker Desktop.
2. Apple Silicon / Intel Macs **cannot** use the NVIDIA Ollama container. Use deterministic-only mode:
   ```bash
   # in .env:  LLM_NARRATIVE_ENABLED=false
   docker compose up -d --build iam-sentinel   # start only the API service
   ```
   (Optional narrative on Mac: install native Ollama from https://ollama.com, then set
   `OLLAMA_BASE_URL=http://host.docker.internal:11434` and `LLM_NARRATIVE_ENABLED=true`.)

### 🐧 Linux (Docker Engine)
1. Deterministic-only:
   ```bash
   docker compose up -d --build iam-sentinel
   ```
2. With GPU narrative: install the **NVIDIA Container Toolkit**
   (https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html), then:
   ```bash
   docker compose up -d --build            # starts API + Ollama
   docker compose exec cyber-brain ollama pull qwen2.5-coder:7b
   ```

### 🐧🪟 WSL (Ubuntu on Windows)
1. Install WSL2 + Ubuntu (`wsl --install`), install Docker Desktop and enable
   **Settings → Resources → WSL Integration** for your distro (or install Docker Engine inside WSL).
2. For GPU: install the NVIDIA CUDA driver for WSL on Windows + the NVIDIA Container Toolkit inside WSL.
3. From the unzipped folder inside WSL:
   ```bash
   docker compose up -d --build
   docker compose exec cyber-brain ollama pull qwen2.5-coder:7b
   ```

---

## 4. Verify

```bash
curl -s http://127.0.0.1:8080/api/health     # attestation: versions, auth, providers
curl -s http://127.0.0.1:8080/api/readyz      # {"ready": true}
```
Open the dashboard: **http://127.0.0.1:8080**  ·  Pricing page: **http://127.0.0.1:8080/pricing**

## 5. First audit

```bash
curl -s http://127.0.0.1:8080/api/audit/iam \
  -H "X-API-Key: YOUR_ANALYST_SECRET" -H "Content-Type: application/json" \
  -d '{"policy_json":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}","target":"demo"}'
```
Or just use the dashboard: paste a policy → **Audit Policy**. Try the AWS/Azure/GCP presets.

## 6. Use it inside your IDE (MCP)

In Claude Code / Cursor MCP settings:
```json
{ "mcpServers": { "iam-sentinel": {
    "command": "python3",
    "args": ["/ABSOLUTE/PATH/TO/iam-sentinel/mcp_stdio.py"],
    "env": { "AUTH_ENABLED": "false", "LLM_NARRATIVE_ENABLED": "false" }
}}}
```
Then ask your assistant: *"Audit this IAM policy with iam-sentinel."* (The dashboard's
**🔌 MCP Setup** button copies this snippet for you.)

---

## Deterministic-only mode (no model, works everywhere)

Set `LLM_NARRATIVE_ENABLED=false` in `.env` and start only the API service
(`docker compose up -d iam-sentinel`). You still get: every finding, severity, evidence,
provenance, and a per-finding fix hint. Only the long prose narrative is skipped.

## TLS (optional)

```bash
python gen_self_signed_cert.py --host iam-sentinel.internal --out ./certs
# then in .env:
TLS_CERT_FILE=/app/certs/server.crt
TLS_KEY_FILE=/app/certs/server.key
```
For production use a cert from your internal CA. Or terminate TLS at a reverse proxy.

## Backup & upgrade

- **Backup:** the audit trail + findings live in the Docker volume `sentinel_data`
  (`/app/data/iam_sentinel.db`). Snapshot that volume.
- **Upgrade:** unzip the new release over the folder, `docker compose up -d --build`. The
  data volume persists.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `database is locked` on a network share | Put `DATA_DIR` on a local disk (WAL falls back automatically, but local is best). |
| `401 Missing or invalid API key` | Send `X-API-Key: <secret>` matching a key in `.env`. |
| `402 quota reached` | Community tier hit its monthly limit — upgrade or wait for reset. |
| Narrative says "unavailable" | The model backend is down/disabled — findings are still complete and authoritative. |
| Port 8080 in use | Set `SERVER_PORT` in `.env` and remap the compose port. |

## Uninstall

```bash
docker compose down            # keep data
docker compose down -v         # also delete the audit data volume
```
