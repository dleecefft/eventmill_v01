#!/bin/bash
# =============================================================================
# Event Mill v0.1.0 — GCS Service Account Key Generator
# =============================================================================
#
# Creates a JSON key for the eventmill-runner service account and uploads
# it to Secret Manager. Run this on the deploy server after provisioning.
#
# Prerequisites:
#   - provision-gcp-project.sh has been run (SA and secret exist)
#   - gcloud CLI authenticated with IAM and Secret Manager access
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   bash cloud_install/create-gcs-sa-key.sh
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"
SA_NAME="eventmill-runner"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
SECRET_NAME="eventmill-gcs-sa"
TEMP_KEY_FILE="/tmp/eventmill-sa-key-$$.json"

echo "🔑 Event Mill — GCS Service Account Key Generator"
echo "==================================================="
echo "Project:         ${PROJECT_ID}"
echo "Service Account: ${SA_EMAIL}"
echo "Secret:          ${SECRET_NAME}"
echo ""

if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    echo "  export GOOGLE_CLOUD_PROJECT=\"your-project-id\""
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Verify service account exists
# ---------------------------------------------------------------------------

echo "🔍 Verifying service account exists..."
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    echo "ERROR: Service account '${SA_EMAIL}' not found."
    echo "  Run provision-gcp-project.sh first to create it."
    exit 1
fi
echo "   ✓ Service account exists"
echo ""

# ---------------------------------------------------------------------------
# Step 2: Verify secret exists
# ---------------------------------------------------------------------------

echo "🔍 Verifying secret exists..."
if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    echo "ERROR: Secret '${SECRET_NAME}' not found."
    echo "  Run provision-gcp-project.sh first to create it."
    exit 1
fi
echo "   ✓ Secret exists"
echo ""

# ---------------------------------------------------------------------------
# Step 3: Generate new service account key
# ---------------------------------------------------------------------------

echo "🔐 Generating service account key..."
gcloud iam service-accounts keys create "${TEMP_KEY_FILE}" \
    --iam-account="${SA_EMAIL}" \
    --project="${PROJECT_ID}" \
    --quiet

if [ ! -f "${TEMP_KEY_FILE}" ]; then
    echo "ERROR: Failed to create key file."
    exit 1
fi

echo "   ✓ Key generated: ${TEMP_KEY_FILE}"
echo ""

# ---------------------------------------------------------------------------
# Step 4: Upload key to Secret Manager
# ---------------------------------------------------------------------------

echo "📤 Uploading key to Secret Manager..."
gcloud secrets versions add "${SECRET_NAME}" \
    --project="${PROJECT_ID}" \
    --data-file="${TEMP_KEY_FILE}" \
    --quiet

echo "   ✓ Key uploaded to secret '${SECRET_NAME}'"
echo ""

# ---------------------------------------------------------------------------
# Step 5: Clean up local key file
# ---------------------------------------------------------------------------

echo "🧹 Cleaning up temporary key file..."
rm -f "${TEMP_KEY_FILE}"
echo "   ✓ Temporary key file deleted"
echo ""

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo "==================================================="
echo "✅ GCS service account key created and stored!"
echo ""
echo "The key is now available in Secret Manager:"
echo "  gcloud secrets versions list ${SECRET_NAME} --project=${PROJECT_ID}"
echo ""
echo "Cloud Run will mount this key at:"
echo "  /app/credentials/sa-key.json"
echo ""
echo "To redeploy with the new key:"
echo "  bash cloud_install/deploy-cloudrun-secrets.sh"
echo ""
