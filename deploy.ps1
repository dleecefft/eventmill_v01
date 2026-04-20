# Event Mill - Build & Deploy to Cloud Run
# Usage: .\deploy.ps1

param(
    [string]$Project = "apm0008778-prd-eltetl-80",
    [string]$Region = "northamerica-northeast2",
    [string]$Service = "threatbrief-fusion",
    [string]$BuildConfig = "build-threatbrief-fusion.yaml"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Event Mill - Cloud Run Deploy ===" -ForegroundColor Cyan
Write-Host "Project: $Project" -ForegroundColor Yellow
Write-Host "Region: $Region" -ForegroundColor Yellow
Write-Host "Service: $Service" -ForegroundColor Yellow
Write-Host ""

# Step 1: Build Docker image
Write-Host "Step 1: Building Docker image..." -ForegroundColor Green
gcloud builds submit --project=$Project --config=$BuildConfig . | Tee-Object -Variable buildOutput

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Build successful" -ForegroundColor Green
Write-Host ""

# Step 2: Deploy to Cloud Run
Write-Host "Step 2: Deploying to Cloud Run..." -ForegroundColor Green
$ImageUri = "${Region}-docker.pkg.dev/${Project}/eventmill/${Service}:latest"

$deployArgs = @(
    "run", "deploy", $Service,
    "--region=$Region",
    "--project=$Project",
    "--image=$ImageUri",
    "--platform=managed",
    "--port=8080",
    "--memory=1Gi",
    "--cpu=2",
    "--timeout=3600",
    "--min-instances=0",
    "--max-instances=3",
    "--concurrency=10",
    "--service-account=eventmill-runner@${Project}.iam.gserviceaccount.com",
    "--set-env-vars=EVENTMILL_BUCKET_PREFIX=eventmill,EVENTMILL_LOG_LEVEL=INFO",
    "--allow-unauthenticated"
)
& gcloud @deployArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "Deployment failed!" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Deployment successful" -ForegroundColor Green
Write-Host ""
Write-Host "Service URL:" -ForegroundColor Cyan
gcloud run services describe $Service --region=$Region --project=$Project --format='value(status.url)'
