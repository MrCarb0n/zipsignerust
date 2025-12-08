#!/bin/bash
set -euo pipefail

RELEASE_TYPE="${1}"
TAG_NAME="${2}"
REPO_NAME="${3}"
RUN_ID="${4}"
SHA="${5}"

SHORT_SHA=$(echo "${SHA}" | cut -c1-8)
DATE=$(date +'%Y-%m-%d %H:%M:%S UTC')
DATE_BADGE="${DATE// /%20}"
WORKFLOW_URL="https://github.com/${REPO_NAME}/actions/runs/${RUN_ID}"
DL_BASE="https://github.com/${REPO_NAME}/releases/download/${TAG_NAME}"

if [[ "${RELEASE_TYPE}" == "versioned" ]]; then
    TITLE_HEADER="**📦 Version ${TAG_NAME} Release**"
    if PREV_TAG=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null); then
        MSG=$(git log --pretty=format:"- %s (%h)" "${PREV_TAG}..HEAD")
        STATS=$(git diff --stat "${PREV_TAG}..HEAD")
    else
        MSG=$(git log --pretty=format:"- %s (%h)")
        STATS=$(git show --stat HEAD)
    fi
else
    TITLE_HEADER="**🚀 Automated Rolling Release**"
    MSG=$(git log -10 --pretty=format:"- %s (%h)")
    if git rev-parse HEAD~1 >/dev/null 2>&1; then
        STATS=$(git diff --stat HEAD~1 HEAD)
    else
        STATS=$(git show --stat HEAD)
    fi
fi

cat <<EOF
<div align="center">

\`\`\`
 _____ _     _____ _             _____         _
|__   |_|___|   __|_|___ ___ ___| __  |_ _ ___| |_
|   __| | . |__   | | . |   | -_|    -| | |_ -|  _|
|_____|_|  _|_____|_|_  |_|_|___|__|__|___|___|_|
        |_|         |___|
\`\`\`

[![Build Date](https://img.shields.io/badge/Date-${DATE_BADGE}-blue)](${WORKFLOW_URL}) [![Commit](https://img.shields.io/badge/Commit-${SHORT_SHA}-informational)](${WORKFLOW_URL})

</div>

## 📋 Summary of Changes
\`\`\`text
${MSG}
\`\`\`

## 📊 Code Impact
\`\`\`diff
${STATS}
\`\`\`

## 📦 Artifacts
| Platform | Architecture | Filename | Size |
| :--- | :--- | :--- | :--- |
EOF

for f in all_dist/*; do
    if [[ -f "$f" ]]; then
        FILENAME=$(basename "$f")
        SIZE=$(du -h "$f" | cut -f1)
        case "$FILENAME" in
        *linux*)
            PLATFORM="🐧 Linux"
            ARCH="x86_64"
            ;;
        *android*)
            PLATFORM="🤖 Android"
            ARCH="ARM64"
            ;;
        *windows*)
            PLATFORM="🪟 Windows"
            ARCH="x86_64"
            ;;
        *)
            PLATFORM="Unknown"
            ARCH="Unknown"
            ;;
        esac
        echo "| ${PLATFORM} | ${ARCH} | [${FILENAME}](${DL_BASE}/${FILENAME}) | ${SIZE} |"
    fi
done

echo ""
echo '<div align="center">'
echo ""
echo "${TITLE_HEADER}"
echo ""
echo '</div>'
