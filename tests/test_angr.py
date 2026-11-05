import os
import shutil
import subprocess

import pytest

pytest.importorskip("angr")
from app.schema import Arch  # noqa: E402
from app.taint_angr import analyse_binary  # noqa: E402

C_SRC = r'''
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void handle(char *in){ char buf[16]; strcpy(buf,in); printf("%s\n",buf); }
void run(char *cmd){ system(cmd); }
int main(int argc,char**argv){ if(argc>1){handle(argv[1]);run(getenv("X")?getenv("X"):"true");} return 0; }
'''


@pytest.mark.skipif(not shutil.which("gcc"), reason="gcc missing")
def test_sink_reachability_with_source(tmp_path):
    src, exe = tmp_path / "v.c", tmp_path / "vuln"
    src.write_text(C_SRC)
    subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-o", str(exe), str(src)], check=True)
    fs, complete, note = analyse_binary(str(exe), "/bin/vuln", "fw", Arch.X86_64, timeout=120)
    assert complete, note
    sinks = {f.sink for f in fs}
    assert {"strcpy", "system"} <= sinks
    sysf = next(f for f in fs if f.sink == "system")
    assert sysf.cwe == "CWE-78" and sysf.source == "getenv" and sysf.confidence.value == "probable"


def test_timeout_reports_incomplete(tmp_path):
    exe = tmp_path / "x"
    shutil.copy("/bin/ls", exe)
    fs, complete, note = analyse_binary(str(exe), "/bin/x", "fw", Arch.X86_64, timeout=1)
    assert complete is False and "timeout" in note
