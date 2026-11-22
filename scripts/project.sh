# shellcheck shell=bash
# project.sh: sourced by the scripts. They act on the repository in
# $TEMPER_PROJECT_DIR (default: the checkout they are in), so another
# repository can build and release its images with these scripts.
# Its project.env says what it releases as:
#
#   name=temper                              release files: <name>-<date>.*
#   title=Temper                             release title: <title> <date>
#   repo=MaliSec/temper                      GitHub repository
#   release_workflow=temper-release-build.yml   the workflow that signs its releases
#   images=ghcr.io/malisec/temper            images publish as <images>/<name>
#
# Sets TEMPER_HOME (these scripts' checkout), PROJECT_NAME, PROJECT_TITLE,
# PROJECT_REPO, RELEASE_WORKFLOW, PROJECT_IMAGES and SIGNER_RE (the signer
# identity up to the "@", as an anchored regex), and changes to the project
# directory.

TEMPER_HOME=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)
cd "${TEMPER_PROJECT_DIR:-$TEMPER_HOME}" || { echo "TEMPER_PROJECT_DIR $TEMPER_PROJECT_DIR is not a directory" >&2; exit 1; }
TEMPER_PROJECT_DIR=$(pwd)
[ -f project.env ] || { echo "$(pwd)/project.env missing (see scripts/project.sh)" >&2; exit 1; }
PROJECT_NAME="" PROJECT_TITLE="" PROJECT_REPO="" RELEASE_WORKFLOW="" PROJECT_IMAGES=""
while IFS='=' read -r k v || [ -n "$k" ]; do
  case "$k" in
    ''|'#'*) ;;
    name) PROJECT_NAME=$v ;;
    title) PROJECT_TITLE=$v ;;
    repo) PROJECT_REPO=$v ;;
    release_workflow) RELEASE_WORKFLOW=$v ;;
    images) PROJECT_IMAGES=$v ;;
    *) echo "project.env: unknown key '$k'" >&2; exit 1 ;;
  esac
done < project.env
[[ "$PROJECT_NAME" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo "project.env: name '$PROJECT_NAME' is not [a-z0-9-]" >&2; exit 1; }
[ -n "$PROJECT_TITLE" ] || { echo "project.env: no title" >&2; exit 1; }
[[ "$PROJECT_REPO" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] || { echo "project.env: repo '$PROJECT_REPO' is not <owner>/<name>" >&2; exit 1; }
[[ "$RELEASE_WORKFLOW" =~ ^[A-Za-z0-9_.-]+\.ya?ml$ ]] || { echo "project.env: release_workflow '$RELEASE_WORKFLOW' is not a workflow file name" >&2; exit 1; }
# <registry host>/<path>: lower case, no tag, no trailing slash.
IMAGE_REPO_RE='^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$'
[[ "$PROJECT_IMAGES" =~ $IMAGE_REPO_RE ]] || { echo "project.env: images '$PROJECT_IMAGES' is not <registry>/<path>" >&2; exit 1; }
SIGNER_RE="^https://github\.com/${PROJECT_REPO//./\\.}/\.github/workflows/${RELEASE_WORKFLOW//./\\.}"
export TEMPER_HOME TEMPER_PROJECT_DIR PROJECT_NAME PROJECT_TITLE PROJECT_REPO RELEASE_WORKFLOW PROJECT_IMAGES SIGNER_RE
