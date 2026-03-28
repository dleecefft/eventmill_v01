#!/bin/bash
# Event Mill v0.1.0 - Cloud Run Deployment with Secret Manager
# Uses pre-created secrets for production-grade security
#
# Prerequisites:
#   1. Create secrets (see README.md in this directory)
#   2. Set GOOGLE_CLOUD_PROJECT
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   bash cloud_install/deploy-cloudrun-secrets.sh

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"
REGION="${CLOUD_RUN_REGION:-northamerica-northeast2}"
SERVICE_NAME="event-mill"
IMAGE_NAME="${REGION}-docker.pkg.dev/${PROJECT_ID}/eventmill/${SERVICE_NAME}"

# GCS bucket for log artifact storage
GCS_LOG_BUCKET="${GCS_LOG_BUCKET:-digevtrecintake}"

# Secret names (pre-created in GCP Console or via gcloud)
# Dual Gemini keys isolate quota between light (Flash) and heavy (Pro) tiers
SECRET_GEMINI_FLASH="${EVENTMILL_SECRET_GEMINI_FLASH:-eventmill-gemini-flash-api}"
SECRET_GEMINI_PRO="${EVENTMILL_SECRET_GEMINI_PRO:-eventmill-gemini-pro-api}"
SECRET_GCS_SA="${EVENTMILL_SECRET_GCS_SA:-eventmill-gcs-sa}"
SECRET_TTYD_USER="${EVENTMILL_SECRET_TTYD_USER:-eventmill-ttyd-user}"
SECRET_TTYD_CRED="${EVENTMILL_SECRET_TTYD_CRED:-eventmill-ttyd-cred}"

echo "⚙ Event Mill v0.1.0 - Cloud Run Deployment (Secret Manager)"
echo "============================================================="
echo "Project:  ${PROJECT_ID}"
echo "Region:   ${REGION}"
echo "Service:  ${SERVICE_NAME}"
echo ""
echo "🔐 Using secrets:"
echo "   - ${SECRET_GEMINI_FLASH} (Gemini Flash API Key — light tier)"
echo "   - ${SECRET_GEMINI_PRO} (Gemini Pro API Key — heavy tier)"
echo "   - ${SECRET_GCS_SA} (GCS Service Account)"
echo "   - ${SECRET_TTYD_USER} (ttyd username)"
echo "   - ${SECRET_TTYD_CRED} (ttyd password)"
echo ""
echo "📦 GCS Bucket: ${GCS_LOG_BUCKET}"
echo ""

if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Enable required APIs
# ---------------------------------------------------------------------------
echo "📡 Enabling required APIs..."
gcloud services enable secretmanager.googleapis.com --project="${PROJECT_ID}" --quiet
gcloud services enable run.googleapis.com --project="${PROJECT_ID}" --quiet
gcloud services enable cloudbuild.googleapis.com --project="${PROJECT_ID}" --quiet

# ---------------------------------------------------------------------------
# Step 2: Grant Cloud Run service account access to secrets
# ---------------------------------------------------------------------------
echo ""
echo "🔑 Granting Cloud Run access to secrets..."

PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")
SERVICE_ACCOUNT="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

grant_secret_access() {
    local secret_name=$1
    if ! gcloud secrets describe "${secret_name}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
        echo "   WARNING: Secret '${secret_name}' not found - skipping (create it first)"
        return
    fi
    gcloud secrets add-iam-policy-binding "${secret_name}" \
        --project="${PROJECT_ID}" \
        --member="serviceAccount:${SERVICE_ACCOUNT}" \
        --role="roles/secretmanager.secretAccessor" \
        --quiet 2>/dev/null || true
    echo "   OK: Granted access to '${secret_name}'"
}

grant_secret_access "${SECRET_GEMINI_FLASH}"
grant_secret_access "${SECRET_GEMINI_PRO}"
grant_secret_access "${SECRET_GCS_SA}"
grant_secret_access "${SECRET_TTYD_USER}"
grant_secret_access "${SECRET_TTYD_CRED}"

# ---------------------------------------------------------------------------
# Step 3: Build the container image
# ---------------------------------------------------------------------------
echo ""
echo "📦 Building container image..."

# Use Cloud Build with the Cloud Run Dockerfile
cat > /tmp/cloudbuild-eventmill.yaml <<BUILDEOF
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', '${IMAGE_NAME}', '-f', 'cloud_install/Dockerfile.cloudrun', '.']
images:
  - '${IMAGE_NAME}'
BUILDEOF

gcloud builds submit \
    --project="${PROJECT_ID}" \
    --config=/tmp/cloudbuild-eventmill.yaml \
    .

# ---------------------------------------------------------------------------
# Step 4: Deploy to Cloud Run with secrets
# ---------------------------------------------------------------------------
echo ""
echo "🚀 Deploying to Cloud Run..."

gcloud run deploy "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE_NAME}" \
    --platform=managed \
    --port=8080 \
    --memory=512Mi \
    --cpu=1 \
    --min-instances=0 \
    --max-instances=3 \
    --timeout=3600 \
    --concurrency=10 \
    --set-secrets="GEMINI_FLASH_API_KEY=${SECRET_GEMINI_FLASH}:latest,GEMINI_PRO_API_KEY=${SECRET_GEMINI_PRO}:latest,/app/credentials/sa-key.json=${SECRET_GCS_SA}:latest,TTYD_USERNAME=${SECRET_TTYD_USER}:latest,TTYD_PASSWORD=${SECRET_TTYD_CRED}:latest" \
    --set-env-vars="GOOGLE_APPLICATION_CREDENTIALS=/app/credentials/sa-key.json,GCS_LOG_BUCKET=${GCS_LOG_BUCKET},EVENTMILL_LOG_LEVEL=${EVENTMILL_LOG_LEVEL:-INFO}" \
    --allow-unauthenticated

# Note: For authenticated access, replace --allow-unauthenticated with:
#   --no-allow-unauthenticated
# Then grant access via IAM:
#   gcloud run services add-iam-policy-binding event-mill \
#       --region="${REGION}" \
#       --member="user:you@example.com" \
#       --role="roles/run.invoker"

# ---------------------------------------------------------------------------
# Step 5: Display results
# ---------------------------------------------------------------------------
echo ""
echo "✅ Deployment complete!"
echo ""

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --format="value(status.url)")

echo "🌐 Event Mill is available at:"
echo "   ${SERVICE_URL}"
echo ""
echo "🔐 Secrets configured:"
echo "   - GEMINI_FLASH_API_KEY         <- ${SECRET_GEMINI_FLASH}"
echo "   - GEMINI_PRO_API_KEY           <- ${SECRET_GEMINI_PRO}"
echo "   - /app/credentials/sa-key.json <- ${SECRET_GCS_SA}"
echo "   - TTYD_USERNAME               <- ${SECRET_TTYD_USER}"
echo "   - TTYD_PASSWORD               <- ${SECRET_TTYD_CRED}"
echo ""
echo "📦 Environment:"
echo "   - GCS_LOG_BUCKET = ${GCS_LOG_BUCKET}"
echo "   - Region = ${REGION}"
echo ""
echo "📋 To update a secret:"
echo "   echo -n 'new-key' | gcloud secrets versions add ${SECRET_GEMINI_FLASH} --data-file=-"
echo "   echo -n 'new-key' | gcloud secrets versions add ${SECRET_GEMINI_PRO} --data-file=-"
echo "   gcloud secrets versions add ${SECRET_GCS_SA} --data-file=/path/to/new-sa.json"
