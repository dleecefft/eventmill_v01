#!/bin/bash
# =============================================================================
# Event Mill v0.1.0 — GCP Project Provisioning
# =============================================================================
#
# Run this script ONCE to prepare a GCP project for Event Mill.
# It is idempotent — safe to re-run if a step fails partway through.
#
# Prerequisites:
#   - gcloud CLI installed and authenticated (gcloud auth login)
#   - A GCP project already created with billing enabled
#   - Sufficient IAM permissions (Owner or Editor on the project)
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   bash cloud_install/provision-gcp-project.sh
#
# After provisioning, create secrets:
#   bash cloud_install/provision-secrets.sh
#
# Then deploy:
#   bash cloud_install/deploy-cloudrun-secrets.sh
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration — update these or set via environment variables
# ---------------------------------------------------------------------------

# CHANGE THIS: Your GCP project ID
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"

# CHANGE THIS: Deployment region
# See https://cloud.google.com/run/docs/locations for available regions
REGION="${CLOUD_RUN_REGION:-northamerica-northeast2}"

# CHANGE THIS: GCS bucket name for log artifact storage
# Must be globally unique across all of GCP
GCS_LOG_BUCKET="${GCS_LOG_BUCKET:-digevtrecintake}"

# CHANGE THIS: GCS bucket location (should match or be near REGION)
GCS_BUCKET_LOCATION="${GCS_BUCKET_LOCATION:-northamerica-northeast2}"

# Service account name for Event Mill (usually no change needed)
SA_NAME="eventmill-runner"
SA_DISPLAY_NAME="Event Mill Cloud Run Service Account"

# Cloud Run service name (usually no change needed)
SERVICE_NAME="event-mill"

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

echo "⚙ Event Mill v0.1.0 — GCP Project Provisioning"
echo "================================================="
echo ""
echo "Project:  ${PROJECT_ID}"
echo "Region:   ${REGION}"
echo "Bucket:   ${GCS_LOG_BUCKET}"
echo "SA:       ${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo ""

if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    echo "  export GOOGLE_CLOUD_PROJECT=\"your-project-id\""
    exit 1
fi

# Verify gcloud is authenticated and project is accessible
echo "🔍 Verifying project access..."
if ! gcloud projects describe "${PROJECT_ID}" --format="value(projectId)" > /dev/null 2>&1; then
    echo "ERROR: Cannot access project '${PROJECT_ID}'."
    echo "  - Is gcloud authenticated?  gcloud auth login"
    echo "  - Does the project exist?   gcloud projects list"
    exit 1
fi
echo "   OK: Project '${PROJECT_ID}' is accessible."
echo ""

# Capture project number (needed for default compute SA references)
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")

# =============================================================================
# Section 1: Enable APIs
# =============================================================================
# These APIs are required for building, deploying, and running Event Mill
# on Cloud Run with GCS artifact storage and Secret Manager.
# API enablement is idempotent — already-enabled APIs are skipped.
# =============================================================================

echo "📡 Section 1: Enabling GCP APIs..."
echo ""

# Cloud Run — hosts the Event Mill container
echo "   Enabling Cloud Run API (run.googleapis.com)..."
gcloud services enable run.googleapis.com --project="${PROJECT_ID}" --quiet

# Cloud Build — builds container images from source
echo "   Enabling Cloud Build API (cloudbuild.googleapis.com)..."
gcloud services enable cloudbuild.googleapis.com --project="${PROJECT_ID}" --quiet

# Artifact Registry — stores built container images
# (Container Registry is deprecated; Artifact Registry is the replacement)
echo "   Enabling Artifact Registry API (artifactregistry.googleapis.com)..."
gcloud services enable artifactregistry.googleapis.com --project="${PROJECT_ID}" --quiet

# Cloud Storage — stores log artifacts and investigation files
echo "   Enabling Cloud Storage API (storage.googleapis.com)..."
gcloud services enable storage.googleapis.com --project="${PROJECT_ID}" --quiet

# Secret Manager — stores API keys, credentials, and ttyd auth
echo "   Enabling Secret Manager API (secretmanager.googleapis.com)..."
gcloud services enable secretmanager.googleapis.com --project="${PROJECT_ID}" --quiet

# Generative Language (Gemini via AI Studio) — AI-powered analysis
# This is the API used by the google-genai Python SDK with GEMINI_API_KEY
echo "   Enabling Generative Language API (generativelanguage.googleapis.com)..."
gcloud services enable generativelanguage.googleapis.com --project="${PROJECT_ID}" --quiet

# API Keys — required for programmatic API key creation and restriction
echo "   Enabling API Keys API (apikeys.googleapis.com)..."
gcloud services enable apikeys.googleapis.com --project="${PROJECT_ID}" --quiet

# IAM — needed for service account and policy management
echo "   Enabling IAM API (iam.googleapis.com)..."
gcloud services enable iam.googleapis.com --project="${PROJECT_ID}" --quiet

echo ""
echo "   ✓ All APIs enabled."
echo ""

# =============================================================================
# Section 2: Service Account
# =============================================================================
# Create a dedicated service account for Event Mill's Cloud Run service.
# This follows the principle of least privilege — the service only gets
# the permissions it needs, rather than using the broad default compute SA.
# =============================================================================

echo "👤 Section 2: Creating service account..."
echo ""

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    echo "   ✓ Service account already exists: ${SA_EMAIL}"
else
    gcloud iam service-accounts create "${SA_NAME}" \
        --project="${PROJECT_ID}" \
        --display-name="${SA_DISPLAY_NAME}" \
        --description="Service account for Event Mill Cloud Run deployment" \
        --quiet
    echo "   ✓ Created service account: ${SA_EMAIL}"
fi
echo ""

# =============================================================================
# Section 3: IAM Role Bindings
# =============================================================================
# Grant the Event Mill service account only the permissions it needs.
# Each binding is explained below.
# =============================================================================

echo "🔐 Section 3: Configuring IAM roles..."
echo ""

# Allow the SA to read/write objects in GCS (log artifacts)
echo "   Granting Storage Object User (read/write GCS objects)..."
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/storage.objectUser" \
    --quiet > /dev/null 2>&1
echo "   ✓ roles/storage.objectUser"

# Allow the SA to access secrets from Secret Manager
echo "   Granting Secret Manager Secret Accessor..."
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet > /dev/null 2>&1
echo "   ✓ roles/secretmanager.secretAccessor"

# Allow the SA to write structured logs to Cloud Logging
echo "   Granting Logs Writer..."
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/logging.logWriter" \
    --quiet > /dev/null 2>&1
echo "   ✓ roles/logging.logWriter"

# Allow Cloud Build's default SA to deploy to Cloud Run
# (Cloud Build uses the project's default compute SA for builds)
DEFAULT_COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
CLOUDBUILD_SA="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"

echo "   Granting Cloud Build SA permission to deploy to Cloud Run..."
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${CLOUDBUILD_SA}" \
    --role="roles/run.admin" \
    --quiet > /dev/null 2>&1
echo "   ✓ roles/run.admin for Cloud Build SA"

echo "   Granting Cloud Build SA permission to act as Event Mill SA..."
gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${CLOUDBUILD_SA}" \
    --role="roles/iam.serviceAccountUser" \
    --quiet > /dev/null 2>&1
echo "   ✓ roles/iam.serviceAccountUser on ${SA_NAME}"

echo ""

# =============================================================================
# Section 4: GCS Bucket for Log Artifacts
# =============================================================================
# Event Mill reads log files and investigation artifacts from GCS.
# This bucket stores the exported event records that analysts investigate.
# =============================================================================

echo "📦 Section 4: Creating GCS bucket for log artifacts..."
echo ""

if gsutil ls -b "gs://${GCS_LOG_BUCKET}" > /dev/null 2>&1; then
    echo "   ✓ Bucket already exists: gs://${GCS_LOG_BUCKET}"
else
    gsutil mb \
        -p "${PROJECT_ID}" \
        -l "${GCS_BUCKET_LOCATION}" \
        -b on \
        "gs://${GCS_LOG_BUCKET}"
    echo "   ✓ Created bucket: gs://${GCS_LOG_BUCKET}"
fi

# Set lifecycle rule: auto-delete objects older than 90 days (optional)
# CHANGE THIS: Adjust retention period or remove this block if not needed
echo "   Setting 90-day lifecycle rule (auto-delete old artifacts)..."
cat > /tmp/eventmill-lifecycle.json <<'LIFECYCLE'
{
  "rule": [
    {
      "action": {"type": "Delete"},
      "condition": {"age": 90}
    }
  ]
}
LIFECYCLE
gsutil lifecycle set /tmp/eventmill-lifecycle.json "gs://${GCS_LOG_BUCKET}" > /dev/null 2>&1
echo "   ✓ Lifecycle rule set (90-day auto-delete)"
echo ""

# =============================================================================
# Section 5: Artifact Registry
# =============================================================================
# Artifact Registry stores the built Docker images.
# Container Registry (gcr.io) is deprecated — Artifact Registry is the
# supported replacement. Images are pushed to:
#   ${REGION}-docker.pkg.dev/${PROJECT_ID}/eventmill/event-mill
#
# NOTE: Update IMAGE_NAME in deploy scripts to use this path.
# =============================================================================

echo "🐳 Section 5: Artifact Registry..."
echo ""

if gcloud artifacts repositories describe eventmill \
    --project="${PROJECT_ID}" \
    --location="${REGION}" > /dev/null 2>&1; then
    echo "   ✓ Repository already exists: ${REGION}-docker.pkg.dev/${PROJECT_ID}/eventmill"
else
    gcloud artifacts repositories create eventmill \
        --project="${PROJECT_ID}" \
        --repository-format=docker \
        --location="${REGION}" \
        --description="Event Mill container images" \
        --quiet
    echo "   ✓ Created repository: ${REGION}-docker.pkg.dev/${PROJECT_ID}/eventmill"
fi

# =============================================================================
# Section 6: Secret Manager — Create Empty Secrets
# =============================================================================
# Create the secret entries in Secret Manager. Values are added separately
# using provision-secrets.sh (interactive) to avoid storing sensitive
# values in shell history or scripts.
# =============================================================================

echo "🔑 Section 6: Creating Secret Manager entries..."
echo ""

create_secret_if_missing() {
    local secret_name=$1
    local description=$2
    if gcloud secrets describe "${secret_name}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
        echo "   ✓ Secret already exists: ${secret_name}"
    else
        # Create with an empty initial version (placeholder)
        echo -n "placeholder" | gcloud secrets create "${secret_name}" \
            --project="${PROJECT_ID}" \
            --data-file=- \
            --labels="app=eventmill" \
            --quiet
        echo "   ✓ Created secret: ${secret_name} (placeholder value — update via provision-secrets.sh)"
    fi
}

# Gemini API keys — separate keys per model tier to isolate quota
# Flash key handles high-volume light tasks (log scanning, pattern discovery)
# Pro key handles deep reasoning tasks (threat modeling, attack paths)
create_secret_if_missing "eventmill-gemini-flash-api" "Gemini Flash API key (light tier)"
create_secret_if_missing "eventmill-gemini-pro-api" "Gemini Pro API key (heavy tier)"

# GCS service account key — JSON key file for GCS bucket access
# NOTE: Only needed if NOT using workload identity or the default compute SA
create_secret_if_missing "eventmill-gcs-sa" "GCS service account key JSON"

# ttyd web terminal credentials — basic auth for the browser-based shell
create_secret_if_missing "eventmill-ttyd-user" "ttyd web terminal username"
create_secret_if_missing "eventmill-ttyd-cred" "ttyd web terminal password"

echo ""

# =============================================================================
# Section 7: Grant Event Mill SA Access to Its Secrets
# =============================================================================
# Cloud Run needs to read secrets at container startup.
# Grant secret-level access to the Event Mill service account.
# =============================================================================

echo "🔗 Section 7: Binding secrets to service account..."
echo ""

bind_secret_to_sa() {
    local secret_name=$1
    gcloud secrets add-iam-policy-binding "${secret_name}" \
        --project="${PROJECT_ID}" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="roles/secretmanager.secretAccessor" \
        --quiet > /dev/null 2>&1
    echo "   ✓ ${SA_NAME} can read ${secret_name}"
}

bind_secret_to_sa "eventmill-gemini-flash-api"
bind_secret_to_sa "eventmill-gemini-pro-api"
bind_secret_to_sa "eventmill-gcs-sa"
bind_secret_to_sa "eventmill-ttyd-user"
bind_secret_to_sa "eventmill-ttyd-cred"

# Also grant the default compute SA (used by Cloud Build during deploy)
echo ""
echo "   Granting default compute SA access to secrets (for Cloud Build)..."
bind_secret_to_default() {
    local secret_name=$1
    gcloud secrets add-iam-policy-binding "${secret_name}" \
        --project="${PROJECT_ID}" \
        --member="serviceAccount:${DEFAULT_COMPUTE_SA}" \
        --role="roles/secretmanager.secretAccessor" \
        --quiet > /dev/null 2>&1
    echo "   ✓ default-compute can read ${secret_name}"
}

bind_secret_to_default "eventmill-gemini-flash-api"
bind_secret_to_default "eventmill-gemini-pro-api"
bind_secret_to_default "eventmill-gcs-sa"
bind_secret_to_default "eventmill-ttyd-user"
bind_secret_to_default "eventmill-ttyd-cred"

echo ""

# =============================================================================
# Section 8: Summary and Next Steps
# =============================================================================

echo "================================================="
echo "✅ GCP project provisioning complete!"
echo "================================================="
echo ""
echo "Project:          ${PROJECT_ID}"
echo "Region:           ${REGION}"
echo "Service Account:  ${SA_EMAIL}"
echo "GCS Bucket:       gs://${GCS_LOG_BUCKET}"
echo "Artifact Reg:     ${REGION}-docker.pkg.dev/${PROJECT_ID}/eventmill"
echo ""
echo "Secrets created (placeholder values):"
echo "   - eventmill-gemini-flash-api  (Flash / light tier)"
echo "   - eventmill-gemini-pro-api    (Pro / heavy tier)"
echo "   - eventmill-gcs-sa"
echo "   - eventmill-ttyd-user"
echo "   - eventmill-ttyd-cred"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "NEXT STEPS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  1. Add real secret values:"
echo "     bash cloud_install/provision-secrets.sh"
echo ""
echo "  2. Deploy Event Mill:"
echo "     source ~/.eventmill/deploy.env"
echo "     bash cloud_install/deploy-cloudrun-secrets.sh"
echo ""
echo "  3. Upload log files for analysis:"
echo "     gsutil cp /path/to/logs/*.log gs://${GCS_LOG_BUCKET}/"
echo ""
