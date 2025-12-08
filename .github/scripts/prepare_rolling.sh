#!/bin/bash
set -euo pipefail

RELEASE_TYPE="${1}"
REPO_NAME="${2}"
GITHUB_TOKEN="${3}"
TAG_NAME="latest"

if [[ "${RELEASE_TYPE}" != "rolling" ]]; then
    echo "Skipping rolling release preparation."
    exit 0
fi

echo "Cleaning up old release..."

# Check if release exists
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: token ${GITHUB_TOKEN}" \
    "https://api.github.com/repos/${REPO_NAME}/releases/tags/${TAG_NAME}")

if [[ "${HTTP_CODE}" == "200" ]]; then
    RELEASE_ID=$(curl -s -H "Authorization: token ${GITHUB_TOKEN}" \
        "https://api.github.com/repos/${REPO_NAME}/releases/tags/${TAG_NAME}" | jq -r '.id')

    echo "Deleting release ID: ${RELEASE_ID}"
    curl -s -X DELETE -H "Authorization: token ${GITHUB_TOKEN}" \
        "https://api.github.com/repos/${REPO_NAME}/releases/${RELEASE_ID}"
fi

echo "Updating '${TAG_NAME}' tag..."
git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

# Delete remote tag to avoid conflicts
git push origin ":refs/tags/${TAG_NAME}" 2>/dev/null || true

# Retag local HEAD
git tag -fa "${TAG_NAME}" -m "Latest rolling release"

# Push new tag
git push origin "${TAG_NAME}" -f
