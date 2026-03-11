#!/bin/bash

# check-org-repos.sh - Find repos in a GitHub org that are not cloned locally.
#
# Scans all git repos in the current directory, verifies they belong to the
# same GitHub org, then queries GitHub for repos missing locally.
# Prompts to clone each missing repo (Y/N/A).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

extract_org() {
    local url="$1"
    # Handle ssh://git@github.com/org/repo.git
    # Handle git@github.com:org/repo.git
    # Handle https://github.com/org/repo.git
    if [[ "$url" =~ github\.com[:/]+([^/]+)/ ]]; then
        echo "${BASH_REMATCH[1]}"
    fi
}

extract_repo() {
    local url="$1"
    if [[ "$url" =~ /([^/]+)\.git$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [[ "$url" =~ /([^/]+)$ ]]; then
        echo "${BASH_REMATCH[1]}"
    fi
}

declare -A org_counts
declare -A dir_orgs
non_github=()

for dir in "$SCRIPT_DIR"/*/; do
    [ -d "$dir/.git" ] || continue
    dirname="$(basename "$dir")"

    url="$(git -C "$dir" remote get-url origin 2>/dev/null || true)"
    if [ -z "$url" ]; then
        non_github+=("$dirname (no remote)")
        continue
    fi

    org="$(extract_org "$url")"
    if [ -z "$org" ]; then
        non_github+=("$dirname ($url)")
        continue
    fi

    dir_orgs["$dirname"]="$org"
    org_counts["$org"]=$(( ${org_counts["$org"]:-0} + 1 ))
done

# Determine the majority org
majority_org=""
majority_count=0
for org in "${!org_counts[@]}"; do
    if (( org_counts["$org"] > majority_count )); then
        majority_org="$org"
        majority_count=${org_counts["$org"]}
    fi
done

if [ -z "$majority_org" ]; then
    echo "ERROR: No GitHub repos found in $SCRIPT_DIR"
    exit 1
fi

# Report non-majority repos
other_org_dirs=()
for dirname in "${!dir_orgs[@]}"; do
    if [ "${dir_orgs[$dirname]}" != "$majority_org" ]; then
        other_org_dirs+=("$dirname (org: ${dir_orgs[$dirname]})")
    fi
done

echo "Majority org: $majority_org ($majority_count repos)"
echo ""

if [ ${#other_org_dirs[@]} -gt 0 ]; then
    echo "Repos from OTHER orgs (not $majority_org):"
    for entry in "${other_org_dirs[@]}"; do
        echo "  - $entry"
    done
    echo ""
fi

if [ ${#non_github[@]} -gt 0 ]; then
    echo "Non-GitHub repos:"
    for entry in "${non_github[@]}"; do
        echo "  - $entry"
    done
    echo ""
fi

# Query GitHub for all repos in the majority org
echo "Querying GitHub for all repos in $majority_org..."
gh_repos="$(gh repo list "$majority_org" --limit 500 --json name --jq '.[].name' 2>&1)" || {
    echo "ERROR: Failed to query GitHub. Make sure 'gh' is installed and authenticated."
    echo "$gh_repos"
    exit 1
}

# Build set of local repo names belonging to this org
declare -A local_repos
for dirname in "${!dir_orgs[@]}"; do
    if [ "${dir_orgs[$dirname]}" = "$majority_org" ]; then
        local_repos["$dirname"]=1
    fi
done

# Find missing repos
missing=()
while IFS= read -r repo; do
    [ -z "$repo" ] && continue
    if [ -z "${local_repos[$repo]:-}" ]; then
        missing+=("$repo")
    fi
done <<< "$gh_repos"

if [ ${#missing[@]} -eq 0 ]; then
    echo "All $majority_org repos are cloned locally."
    exit 0
fi

echo ""
echo "Found ${#missing[@]} repo(s) in $majority_org not cloned locally:"
for repo in "${missing[@]}"; do
    echo "  - $repo"
done
echo ""

clone_all=false

for repo in "${missing[@]}"; do
    if [ "$clone_all" = true ]; then
        echo "Cloning $majority_org/$repo..."
        git clone "git@github.com:$majority_org/$repo.git" "$SCRIPT_DIR/$repo"
        echo ""
        continue
    fi

    read -rp "Clone $majority_org/$repo? [Y/n/a] " answer </dev/tty
    case "${answer,,}" in
        y|yes|"")
            echo "Cloning $majority_org/$repo..."
            git clone "git@github.com:$majority_org/$repo.git" "$SCRIPT_DIR/$repo"
            echo ""
            ;;
        a|all)
            clone_all=true
            echo "Cloning $majority_org/$repo..."
            git clone "git@github.com:$majority_org/$repo.git" "$SCRIPT_DIR/$repo"
            echo ""
            ;;
        *)
            echo "Skipping $repo"
            echo ""
            ;;
    esac
done

echo "Done."
