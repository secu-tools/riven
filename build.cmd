@echo off
REM Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
REM SPDX-License-Identifier: MIT
REM Riven build script for Windows CMD.
REM Forwards all arguments to build.ps1 - see docs/compilation.md for usage.
REM
REM Binaries: riven_<VER>-<OS>-<ARCH>[.exe]

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
