#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Script: prepare_rolling.sh
# Description: Prepares the repository for a rolling release by cleaning up
#              previous 'latest' releases and resetting the git tag.
# Author: Tiash / @MrCarb0n
# ------------------------------------------------------------------------------

RELEASE_TYPE="${1:?Release type is required}"
REPO_NAME="${2:?Repository name is required}"
GITHUB_TOKEN="${3:?GitHub token is required}"

# Constant for the rolling tag
TAG_NAME="latest"

if [[ "${RELEASE_TYPE}" != "rolling" ]]; then
    echo "::notice::Skipping rolling release preparation (Type: ${RELEASE_TYPE})"
    exit 0
fi

echo "::group::Initialize Rolling Release"

# 1. Check for and delete existing release via API
#    We do this to avoid conflicts when softprops/action-gh-release attempts to create it.
echo "🔍 Checking for existing '${TAG_NAME}' release..."

HTTP_RESPONSE=$(curl -s -w "%{http_code}" -o response.json \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    "https://api.github.com/repos/${REPO_NAME}/releases/tags/${TAG_NAME}")

if [[ "${HTTP_RESPONSE}" == "200" ]]; then
    RELEASE_ID=$(jq -r '.id // empty' response.json)
    if [[ -n "${RELEASE_ID}" ]]; then
        echo "🗑️  Deleting stale release (ID: ${RELEASE_ID})..."
        curl -s -X DELETE -H "Authorization: token ${GITHUB_TOKEN}" \
            "https://api.github.com/repos/${REPO_NAME}/releases/${RELEASE_ID}"
        echo "✅ Release deleted."
    fi
else
    echo "✨ No existing release found (HTTP ${HTTP_RESPONSE}). Proceeding..."
fi
rm -f response.json

# 2. Force-update the git tag
#    This ensures 'latest' always points to the commit currently being built.
echo "🏷️  Updating '${TAG_NAME}' tag..."
git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

# Delete remote tag first to prevent 'already exists' ref errors
git push origin ":refs/tags/${TAG_NAME}" 2>/dev/null || true

# Retag local HEAD
git tag -fa "${TAG_NAME}" -m "Latest rolling release"

# Push new tag
git push origin "${TAG_NAME}" -f

echo "::endgroup::"
