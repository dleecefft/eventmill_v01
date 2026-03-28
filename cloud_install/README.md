# Event Mill v0.2.0 — Cloud Installation Guide

Deployment scripts for running Event Mill on Google Cloud Run with a
[ttyd](https://github.com/tsl0922/ttyd) web terminal frontend.

## Architecture

```
Browser (HTTPS:443) → Cloud Run → ttyd (:8080) → eventmill CLI shell
```

Cloud Run provides automatic HTTPS, scaling (0→N), and IAM-based access control.
The ttyd web terminal gives analysts a browser-based Metasploit-style shell.

## Deployment Workflow

Deployments are run from a **dedicated Linux server** with the Google Cloud
SDK and libraries pre-installed. The workflow is:

```
1. SSH into Linux deploy server
2. Pull latest code from GitHub
3. Authenticate to GCP (if session expired)
4. Source deploy config
5. Run deploy script
```

```bash
ssh deploy-server
cd ~/eventmill_v01
git pull
source ~/.eventmill/deploy.env
bash cloud_install/deploy-cloudrun-secrets.sh
```

## First-Time Setup (Deploy Server)

Run the bootstrap script once on the Linux deploy server:

```bash
# Download and run directly, or clone first
curl -sL https://raw.githubusercontent.com/dleecefft/eventmill_v01/main/cloud_install/setup-deploy-server.sh | bash
```

Or manually:

```bash
git clone https://github.com/dleecefft/eventmill_v01.git ~/eventmill_v01
bash ~/eventmill_v01/cloud_install/setup-deploy-server.sh
```

This will:
- Verify `gcloud` and `docker` are available
- Clone or pull the repo to `~/eventmill_v01`
- Create `~/.eventmill/deploy.env` config template
- Make deploy scripts executable

Then configure:

```bash
nano ~/.eventmill/deploy.env     # Set project ID, region, secret names
gcloud auth login                # Authenticate to GCP
gcloud config set project YOUR_PROJECT_ID
```

## Deploy Commands

### Production deploy (Secret Manager — recommended)

```bash
source ~/.eventmill/deploy.env
cd ~/eventmill_v01
git pull
bash cloud_install/deploy-cloudrun-secrets.sh
```

### Quick deploy (env var secrets — dev/testing only)

```bash
source ~/.eventmill/deploy.env
export GEMINI_API_KEY="your-key"
export TTYD_USERNAME="admin"
export TTYD_PASSWORD="changeme"
cd ~/eventmill_v01
bash cloud_install/deploy-cloudrun.sh
```

### CI/CD via Cloud Build

Connect GitHub repo to Cloud Build, then trigger manually:

```bash
cd ~/eventmill_v01
gcloud builds submit \
    --project="${GOOGLE_CLOUD_PROJECT}" \
    --config=cloud_install/cloudbuild.yaml \
    .
```

## Files

| File | Purpose |
|------|---------|
| `setup-deploy-server.sh` | One-time bootstrap for the Linux deploy server |
| `Dockerfile.cloudrun` | Multi-stage container image with ttyd + eventmill |
| `deploy-cloudrun.sh` | Basic Cloud Run deploy (env var secrets) |
| `deploy-cloudrun-secrets.sh` | Production deploy with GCP Secret Manager |
| `cloudbuild.yaml` | Cloud Build CI/CD pipeline |
| `docker-compose.cloudrun.yml` | Local testing of the Cloud Run image |

## Secret Manager Setup

Create these secrets on the deploy server before the first production deploy:

```bash
# Gemini API key
echo -n "your-api-key" | gcloud secrets create eventmill-gemini-api --data-file=-

# ttyd basic auth credentials
echo -n "analyst" | gcloud secrets create eventmill-ttyd-user --data-file=-
echo -n "strong-password" | gcloud secrets create eventmill-ttyd-cred --data-file=-

# (Optional) GCS service account key for artifact storage
gcloud secrets create eventmill-gcs-sa --data-file=/path/to/sa-key.json
```

## Local Image Testing (on deploy server)

```bash
docker compose -f cloud_install/docker-compose.cloudrun.yml up --build
# Open http://deploy-server:8080 in browser
```

## Configuration Reference

### ~/.eventmill/deploy.env

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | Yes | GCP project ID |
| `CLOUD_RUN_REGION` | No | Deploy region (default: `northamerica-northeast2`) |
| `GCS_LOG_BUCKET` | No | GCS bucket for log artifact storage |
| `EVENTMILL_SECRET_GEMINI` | No | Secret Manager name for Gemini key |
| `EVENTMILL_SECRET_GCS_SA` | No | Secret Manager name for GCS SA key |
| `EVENTMILL_SECRET_TTYD_USER` | No | Secret Manager name for ttyd username |
| `EVENTMILL_SECRET_TTYD_CRED` | No | Secret Manager name for ttyd password |
| `EVENTMILL_LOG_LEVEL` | No | Logging level (default: `INFO`) |

### Runtime environment (set by deploy scripts)

| Variable | Description |
|----------|-------------|
| `GEMINI_API_KEY` | Gemini API key (injected from Secret Manager) |
| `ANTHROPIC_API_KEY` | Anthropic API key (alternative LLM) |
| `TTYD_USERNAME` | ttyd basic auth username |
| `TTYD_PASSWORD` | ttyd basic auth password |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCS service account JSON |
