#!/usr/bin/env bash
# FLS Community signed-release bootstrap. No disks are partitioned here.
set -euo pipefail
umask 077
readonly release_tag='v0.76.0-rc.9'
readonly release_version='0.76.0'
readonly release_name='fls-community-0.76.0-rc.9-linux-amd64.tar.gz'
readonly release_base="https://github.com/frknozel/fls-community/releases/download/${release_tag}"
mode='plan'
explicit_mode=''
for argument in "$@"; do
    case "$argument" in
        --apply|--plan|--check)
            [[ -z "$explicit_mode" || "$explicit_mode" == "$argument" ]] || {
                printf '%s\n' 'Choose only one of --plan, --check or --apply.' >&2; exit 2;
            }
            explicit_mode="$argument"; mode="${argument#--}" ;;
        --inventory|--inventory=*)
            printf '%s\n' 'Synthetic inventories are supported only by the local Python planner.' >&2
            exit 2 ;;
    esac
done
if [[ "$mode" != 'apply' ]]; then
    installer_source="${BASH_SOURCE[0]:-}"
    if [[ -n "$installer_source" && -f "$installer_source" ]]; then
        installer_directory="$(cd -- "$(dirname -- "$installer_source")" && pwd -P)"
        if [[ -f "$installer_directory/bin/fls-install.py" ]]; then
            exec python3 -B "$installer_directory/bin/fls-install.py" "$@"
        fi
    fi
fi
[[ "$EUID" == 0 ]] || { printf '%s\n' 'Run the standalone installer or checker as root.' >&2; exit 2; }
# Apply refuses existing installations before downloads. Check/plan may inspect them.
if [[ "$mode" == 'apply' ]]; then
    for marker in /etc/fls /var/www/fls /var/lib/fls-community-install /srv/fls-server /srv/fortigate /srv/fls-storage /var/lib/mysql/mysql; do
        if [[ -e "$marker" || -L "$marker" ]]; then
            printf '%s\n' 'Fresh Ubuntu required. Existing FLS/database/storage state was detected.' >&2
            exit 2
        fi
    done
fi
# shellcheck disable=SC1091
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 && "$(dpkg --print-architecture)" == amd64 ]] || {
    printf '%s\n' 'This release supports Ubuntu 24.04 amd64 only.' >&2; exit 2;
}
for command_name in curl openssl python3; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf '%s\n' 'Install bootstrap tools first: sudo apt-get update && sudo apt-get install curl ca-certificates openssl python3' >&2
        exit 2
    }
done
bootstrap_work="$(mktemp -d /tmp/fls-community.XXXXXXXX)"
trap 'rm -rf -- "$bootstrap_work"' EXIT
cat > "$bootstrap_work/publisher.pem" <<'KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5jHuE4Bm1rrGDGVH/xxKqSzk6JKQNVz9Pj4nZT9hgsM=
-----END PUBLIC KEY-----
KEY
download() {
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --max-redirs 5 --connect-timeout 20 --max-time 1200 --retry 2 --max-filesize "$3" \
        --output "$2" "$release_base/$1"
}
printf '%s\n' "Verifying FLS Community ${release_tag}..."
download release.json "$bootstrap_work/release.json" 16384
download release.json.sig "$bootstrap_work/release.json.sig" 64
[[ "$(stat -c %s "$bootstrap_work/release.json.sig")" == 64 ]] || exit 2
openssl pkeyutl -verify -pubin -inkey "$bootstrap_work/publisher.pem" -rawin \
    -in "$bootstrap_work/release.json" -sigfile "$bootstrap_work/release.json.sig" >/dev/null
# Signature is checked before the signed filename, length or checksum are used.
python3 -B - "$bootstrap_work/release.json" "$release_version" "$release_tag" "$release_name" <<'PY'
import json, re, sys
from pathlib import Path
p=Path(sys.argv[1]); raw=p.read_bytes()
if not 1 <= len(raw) <= 16384: raise SystemExit('Release manifest size invalid')
m=json.loads(raw)
if (m.get('schema') != 'fls-community-release-v1' or m.get('version') != sys.argv[2]
    or m.get('tag') != sys.argv[3] or m.get('filename') != sys.argv[4]
    or type(m.get('bytes')) is not int or not 1 <= m['bytes'] <= 256*1024**2
    or not re.fullmatch('[a-f0-9]{64}',str(m.get('sha256')))):
    raise SystemExit('Release manifest invalid')
PY
download "$release_name" "$bootstrap_work/package.tar.gz" 268435456
python3 -B - "$bootstrap_work" <<'PY'
# BEGIN FLS SAFE EXTRACTION (covered by tests/community_release_check.py)
import hashlib, json, os, stat, sys, tarfile
from pathlib import Path, PurePosixPath

def extract_release(work):
    work=Path(work)
    manifest=json.loads((work/'release.json').read_text())
    package=work/'package.tar.gz'
    if package.stat().st_size != manifest['bytes']:
        raise ValueError('release_size_mismatch')
    with package.open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest()!=manifest['sha256']:
            raise ValueError('release_checksum_mismatch')
    target=work/'source'; target.mkdir(mode=0o700)
    with tarfile.open(package,'r:gz') as archive:
        members=archive.getmembers()
        if not 1 <= len(members) <= 4096: raise ValueError('release_member_count_invalid')
        seen=set(); total=0
        for member in members:
            name=member.name; parts=name.split('/')
            if (not name or name in seen or '\\' in name or '\x00' in name
                or any(part in ('','..','.') for part in parts)
                or parts[0]!='fls-community' or len(parts)<2
                or not member.isfile() or member.mode not in (0o644,0o755)
                or not 0<=member.size<=32*1024**2):
                raise ValueError('release_member_invalid')
            seen.add(name); total+=member.size
            if total>256*1024**2: raise ValueError('release_unpacked_size_invalid')
        for member in members:
            destination=target/PurePosixPath(member.name)
            destination.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
            data=archive.extractfile(member)
            fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,member.mode)
            with os.fdopen(fd,'wb') as out:
                remaining=member.size
                while remaining:
                    block=data.read(min(remaining,1024**2))
                    if not block: raise ValueError('release_member_truncated')
                    out.write(block);remaining-=len(block)
            destination.chmod(member.mode)
    app=target/'fls-community'
    if not (app/'bin/fls-install.py').is_file(): raise ValueError('installer_missing')
    return app

if __name__=='__main__':
    extract_release(sys.argv[1])
# END FLS SAFE EXTRACTION
PY
python3 -B "$bootstrap_work/source/fls-community/bin/fls-install.py" "$@"
