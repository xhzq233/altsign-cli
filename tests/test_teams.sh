#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT
# Reuse the production compiler/linker flags without replacing the CLI binary.
python3 - "$TEST_ROOT" <<'PY'
import pathlib,sys
root = pathlib.Path(sys.argv[1])
s = pathlib.Path('build.sh').read_text().replace('OUTPUT="altsign-cli"', 'OUTPUT="' + str(root / 'test') + '"')
s = s.replace('    main.mm \\', '    tests/test_teams.mm \\')
(root / 'build.sh').write_text(s)
PY
bash "$TEST_ROOT/build.sh"
HOME="$TEST_ROOT" CFFIXED_USER_HOME="$TEST_ROOT" TMPDIR="$TEST_ROOT" "$TEST_ROOT/test"
# Help must complete with no credentials and no state/log creation.
python3 - "$PWD/altsign-cli" "$TEST_ROOT" <<'PY'
import os,pathlib,subprocess,sys
binary = sys.argv[1]
root = pathlib.Path(sys.argv[2]) / 'help-home'
root.mkdir()
env = dict(os.environ, HOME=str(root), CFFIXED_USER_HOME=str(root), TMPDIR=str(root))
for args in [['--help'], ['-h'], ['help'], ['help','list'], ['help','sign'], ['list','--help'], ['sign','--help'], ['list','-h'], ['sign','-h']]:
    result = subprocess.run([binary] + args, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
    assert result.returncode == 0, args
    assert not list(root.iterdir()), args
for args in [['help','unknown'], ['list','--team-id',''], ['sign','--team-id']]:
    result = subprocess.run([binary] + args, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
    assert result.returncode == 64, args
    assert not list(root.iterdir()), args
print('[altsign-test] Help and invalid team arguments have no state side effects')
PY
