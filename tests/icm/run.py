#!/usr/bin/env python3
from pathlib import Path
import os
import subprocess

root = Path(__file__).resolve().parents[2]
build = root / "build/icm-tests"
build.mkdir(parents=True, exist_ok=True)
cmsis = Path(os.environ.get("ICM_CMSIS_ATMEL", str(Path.home() / ".platformio/packages/framework-cmsis-atmel")))
openssl = Path(os.environ.get("OPENSSL_ROOT", "/opt/homebrew/opt/openssl"))
subprocess.run(["c++", "-std=c++14", "-Wall", "-Wextra", "-Wno-deprecated-declarations",
    "-Wno-unused-function", "-I" + str(root / "tests/icm"),
    "-I" + str(cmsis / "CMSIS/Device/ATMEL/same54/include"),
    "-I" + str(openssl / "include"), str(root / "tests/icm/main.cpp"),
    "-L" + str(openssl / "lib"), "-lcrypto", "-o", str(build / "icm-test")], check=True)
subprocess.run([str(build / "icm-test")], check=True)
