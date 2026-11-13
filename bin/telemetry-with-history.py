#!/usr/bin/python3
"""Keep both children in the credential-bearing telemetry process namespace."""
import subprocess,sys
from pathlib import Path

def main():
    root=Path(__file__).resolve().parent
    sample=subprocess.run([sys.executable,str(root/'telemetry.py')])
    if sample.returncode:return sample.returncode
    try:
        subprocess.run(['/usr/bin/php','-d','memory_limit=64M',str(root/'backlog-history.php')],check=True,timeout=12)
    except (OSError,subprocess.SubprocessError) as error:
        print('FLS backlog history recorder unavailable: '+type(error).__name__,file=sys.stderr)
    return 0

if __name__=='__main__':raise SystemExit(main())
