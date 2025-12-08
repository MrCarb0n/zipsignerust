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

echo "🧹 Cleaning up old rolling release..."

# 1. Delete the Release (so GitHub doesn't get confused)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: token ${GITHUB_TOKEN}" \
    "https://api.github.com/repos/${REPO_NAME}/releases/tags/${TAG_NAME}")

if [[ "${HTTP_CODE}" == "200" ]]; then
    RELEASE_ID=$(curl -s -H "Authorization: token ${GITHUB_TOKEN}" \
        "https://api.github.com/repos/${REPO_NAME}/releases/tags/${TAG_NAME}" | jq -r '.id')

    echo "Deleting release ID: ${RELEASE_ID}"
    curl -s -X DELETE -H "Authorization: token ${GITHUB_TOKEN}" \
        "https://api.github.com/repos/${REPO_NAME}/releases/${RELEASE_ID}"
fi

# 2. Delete the Remote Tag (so the Action can recreate it on the NEW commit)
echo "Deleting old remote tag '${TAG_NAME}'..."
git push origin ":refs/tags/${TAG_NAME}" 2>/dev/null || true

echo "✅ Clean up complete. Ready for new release creation."
