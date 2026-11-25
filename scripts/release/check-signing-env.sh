#!/usr/bin/env bash
# Checks the GitHub environment `release-signing` before the project key is asked for (M13-D38).
#
#   scripts/release/check-signing-env.sh <dry-run|binaries|rehearsal|rehearsal-finalize|tag>
#
# Calls GitHub's API with `gh api` (the token in GH_TOKEN; the repository in GITHUB_REPOSITORY,
# owner/name), in this order, each call failing closed:
#   1. GET repos/<repo>/environments. An error (a 403 included) fails in every mode. In mode dry-run,
#      no `release-signing` in the list prints "release-signing: not configured (total_count <n>)"
#      and exits 0.
#   2. GET repos/<repo>/environments/release-signing. Passes only when can_admins_bypass is false
#      (absent, null or true fails); protection_rules hold a required_reviewers rule with at least one
#      reviewer; deployment_branch_policy is an object with custom_branch_policies true and
#      protected_branches false (null means every branch may deploy).
#   3. Only after custom_branch_policies is true: GET .../environments/release-signing/
#      deployment-branch-policies. Passes only with total_count 1 and the one policy named main, of
#      type branch.
# A non-200 answer, a missing member or a member of another type is a failure. Mode dry-run prints
# the verdict and exits 0 (only call 1 can fail it); every other mode exits 1 on any failure.
# It reads settings only: it changes nothing and reads no secret.
# bash 3.2 compatible (D30).
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

[ "$#" -eq 1 ] || {
  echo "usage: ${0##*/} <dry-run|binaries|rehearsal|rehearsal-finalize|tag>" >&2
  exit 2
}
mode=$1
rel_mode_ok "$mode" dry-run binaries rehearsal rehearsal-finalize tag
rel_need gh jq
repo=${GITHUB_REPOSITORY:-}
printf '%s\n' "$repo" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' || rel_die "GITHUB_REPOSITORY is not owner/name"

# 1. The list of environments: an error fails in every mode.
envs=$(gh api "repos/$repo/environments") || rel_die "GET repos/$repo/environments failed (the token cannot read the environments)"
count=$(printf '%s\n' "$envs" | jq -er '.total_count | if type == "number" then . else error("total_count") end') ||
  rel_die "the environments answer has no numeric total_count"
present=$(printf '%s\n' "$envs" | jq -er '.environments | if type == "array" then (any(.[]; .name == "release-signing") | tostring) else error("environments") end') ||
  rel_die "the environments answer has no environments array"
if [ "$present" != true ]; then
  if [ "$mode" = dry-run ]; then
    echo "release-signing: not configured (total_count $count)"
    exit 0
  fi
  rel_die "release-signing: not configured (total_count $count); create it as RELEASING.md says"
fi

problems=()
problem() { problems+=("$1"); }

# 2. The environment itself.
if env_json=$(gh api "repos/$repo/environments/release-signing"); then
  printf '%s\n' "$env_json" | jq -e '.can_admins_bypass == false' >/dev/null 2>&1 ||
    problem "can_admins_bypass is not false (administrators may bypass the rules)"
  printf '%s\n' "$env_json" | jq -e '[.protection_rules[] | select(.type == "required_reviewers" and (.reviewers | type == "array" and length >= 1))] | length >= 1' >/dev/null 2>&1 ||
    problem "no required_reviewers rule with at least one reviewer"
  custom=false
  if printf '%s\n' "$env_json" | jq -e '.deployment_branch_policy | type == "object" and .custom_branch_policies == true and .protected_branches == false' >/dev/null 2>&1; then
    custom=true
  else
    problem "deployment_branch_policy is not custom branch policies only (custom_branch_policies true, protected_branches false)"
  fi
  # 3. The branch policies, only once custom policies are on (the endpoint is a 404 otherwise).
  if [ "$custom" = true ]; then
    if pol=$(gh api "repos/$repo/environments/release-signing/deployment-branch-policies"); then
      printf '%s\n' "$pol" | jq -e '.total_count == 1 and (.branch_policies | type == "array" and length == 1) and .branch_policies[0].name == "main" and .branch_policies[0].type == "branch"' >/dev/null 2>&1 ||
        problem "the branch policies are not exactly one: the branch main"
    else
      problem "GET deployment-branch-policies failed"
    fi
  fi
else
  problem "GET repos/$repo/environments/release-signing failed"
fi

if [ "${#problems[@]}" -eq 0 ]; then
  echo "release-signing: ok (a required reviewer, no administrator bypass, the branch main only)"
  exit 0
fi
for p in "${problems[@]}"; do
  echo "release-signing: $p" >&2
done
if [ "$mode" = dry-run ]; then
  echo "release-signing: not ready (advice in mode dry-run; every other mode fails here)"
  exit 0
fi
rel_die "release-signing is not configured as RELEASING.md says"
