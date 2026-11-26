#!/bin/sh
# Looks for chrony releases newer than the newest in ci/chrony-versions.txt
# and tests each one (ci/docker-test.sh). Passing: the version is added to
# the list on a branch and a pull request opened. Failing: an issue is
# opened with the end of the log (once per version). Needs gh,
# authenticated (GH_TOKEN). DRY_RUN=1 only prints what it would do.
set -eu
cd "$(dirname "$0")/.."

releases="https://chrony-project.org/releases/"
list=ci/chrony-versions.txt
newest=$(sort -V "$list" | tail -n 1)

# Final releases only (no -pre), newer than the newest tested.
new=$(curl -fsSL "$releases" \
    | grep -oE 'chrony-[0-9]+\.[0-9]+(\.[0-9]+)?\.tar\.gz' \
    | sed -e 's/^chrony-//' -e 's/\.tar\.gz$//' \
    | { cat; echo "$newest"; } \
    | sort -uV \
    | awk -v newest="$newest" 'seen; $0 == newest { seen = 1 }')

if [ -z "$new" ]; then
    echo "No chrony release newer than $newest."
    exit 0
fi

run() {
    if [ "${DRY_RUN:-0}" = 1 ]; then
        echo "would run: $*"
    else
        "$@"
    fi
}

logs=$(mktemp -d)
for version in $new; do
    echo "::group::chrony $version"
    log="$logs/$version.log"
    if ci/docker-test.sh "$version" >"$log" 2>&1; then
        echo "chrony $version passes."
        branch="ci/chrony-$version"
        run git switch -c "$branch"
        if [ "${DRY_RUN:-0}" != 1 ]; then
            echo "$version" >>"$list"
            sort -uV -o "$list" "$list"
        fi
        run git commit -am "ci: test against chrony $version"
        run git push -u origin "$branch"
        run gh pr create --base main --head "$branch" \
            --title "ci: test against chrony $version" \
            --body "chrony $version was released; the test suite passes against it (\`ci/docker-test.sh $version\`, run by the weekly upstream check). This adds it to the CI matrix."
        run git switch -
    else
        echo "chrony $version FAILS."
        tail -n 40 "$log"
        title="Tests fail against chrony $version"
        if gh issue list --state open --search "\"$title\" in:title" --json number --jq '.[].number' | grep -q .; then
            echo "An issue is already open."
        else
            {
                echo "chrony $version was released and the test suite fails against it (\`ci/docker-test.sh $version\`, run by the weekly upstream check)."
                echo
                echo "End of the log:"
                echo
                echo '```'
                tail -n 80 "$log"
                echo '```'
            } >"$logs/issue.md"
            run gh issue create --title "$title" --body-file "$logs/issue.md"
        fi
    fi
    echo "::endgroup::"
done
