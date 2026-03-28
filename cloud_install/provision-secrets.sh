#!/bin/bash
# =============================================================================
# Event Mill v0.1.0 — Secret Manager Value Provisioning
# =============================================================================
#
# Interactively sets the real values for secrets created by
# provision-gcp-project.sh. Run this after provisioning, or any
# time you need to rotate a secret value.
#
# This script prompts for each value so nothing sensitive appears
# in shell history or script files.
#
# Prerequisites:
#   - provision-gcp-project.sh has been run (secrets exist)
#   - gcloud CLI authenticated with Secret Manager access
#
# Usage:
#   export GOOGLE_CLOUD_PROJECT="your-project-id"
#   bash cloud_install/provision-secrets.sh
#
# To update a single secret later without this script:
#   echo -n "new-value" | gcloud secrets versions add SECRET_NAME --data-file=-
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"

echo "🔐 Event Mill v0.1.0 — Secret Value Provisioning"
echo "=================================================="
echo "Project: ${PROJECT_ID}"
echo ""

if [ "${PROJECT_ID}" = "your-project-id" ]; then
    echo "ERROR: Set GOOGLE_CLOUD_PROJECT before running this script."
    exit 1
fi

# ---------------------------------------------------------------------------
# Helper function
# ---------------------------------------------------------------------------

add_secret_version() {
    local secret_name=$1
    local description=$2
    local is_file=$3  # "file" if the value should be read from a file path

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Secret: ${secret_name}"
    echo "        ${description}"
    echo ""

    # Check if secret exists
    if ! gcloud secrets describe "${secret_name}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
        echo "   WARNING: Secret '${secret_name}' does not exist."
        echo "   Run provision-gcp-project.sh first."
        echo ""
        return
    fi

    # Show current version count
    local version_count
    version_count=$(gcloud secrets versions list "${secret_name}" \
        --project="${PROJECT_ID}" \
        --format="value(name)" 2>/dev/null | wc -l)
    echo "   Current versions: ${version_count}"

    read -r -p "   Update this secret? [y/N]: " confirm
    if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
        echo "   Skipped."
        echo ""
        return
    fi

    if [ "${is_file}" = "file" ]; then
        # Read value from a file path
        read -r -p "   Enter file path: " file_path
        if [ ! -f "${file_path}" ]; then
            echo "   ERROR: File not found: ${file_path}"
            echo ""
            return
        fi
        gcloud secrets versions add "${secret_name}" \
            --project="${PROJECT_ID}" \
            --data-file="${file_path}" \
            --quiet
    else
        # Read value interactively (hidden input)
        read -r -s -p "   Enter value: " secret_value
        echo ""
        if [ -z "${secret_value}" ]; then
            echo "   ERROR: Empty value. Skipping."
            echo ""
            return
        fi
        echo -n "${secret_value}" | gcloud secrets versions add "${secret_name}" \
            --project="${PROJECT_ID}" \
            --data-file=- \
            --quiet
    fi

    echo "   ✓ Secret '${secret_name}' updated."
    echo ""
}

# =============================================================================
# Section 1: Gemini API Key
# =============================================================================
# The google-genai SDK uses this key for AI-powered analysis features
# (threat investigation, log pattern identification, SOC workflows).
#
# Get your key from: https://aistudio.google.com/apikey
# =============================================================================

add_secret_version \
    "eventmill-gemini-api" \
    "Gemini API key (get from https://aistudio.google.com/apikey)"

# =============================================================================
# Section 2: GCS Service Account Key
# =============================================================================
# JSON key file for a service account with Storage Object Viewer/User
# permissions on the log artifact bucket.
#
# NOTE: If your Cloud Run service uses workload identity or the default
# compute service account already has GCS access, you can skip this.
#
# To create a key:
#   gcloud iam service-accounts keys create /tmp/sa-key.json \
#       --iam-account=eventmill-runner@PROJECT_ID.iam.gserviceaccount.com
# =============================================================================

add_secret_version \
    "eventmill-gcs-sa" \
    "GCS service account key JSON file (skip if using workload identity)" \
    "file"

# =============================================================================
# Section 3: ttyd Web Terminal Credentials
# =============================================================================
# Basic auth credentials for the ttyd web terminal frontend.
# These protect the browser-based Event Mill shell from unauthorized access.
#
# Choose a strong password — this is the front door to your analysis platform.
# =============================================================================

add_secret_version \
    "eventmill-ttyd-user" \
    "ttyd web terminal username (e.g., analyst)"

add_secret_version \
    "eventmill-ttyd-cred" \
    "ttyd web terminal password (choose a strong password)"

# =============================================================================
# Done
# =============================================================================

echo "=================================================="
echo "✅ Secret provisioning complete."
echo ""
echo "To verify secrets have valid values:"
echo "  gcloud secrets versions list eventmill-gemini-api --project=${PROJECT_ID}"
echo "  gcloud secrets versions list eventmill-ttyd-user  --project=${PROJECT_ID}"
echo ""
echo "To deploy Event Mill:"
echo "  bash cloud_install/deploy-cloudrun-secrets.sh"
echo ""
