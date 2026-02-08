@echo off
setlocal enabledelayedexpansion
REM Run all Rust + browser integration tests.
REM Usage: run-all-tests.bat

set PASS=0
set FAIL=0
set SKIPPED=0
set FAILURES=

echo ===============================================
echo   Rust tests
echo ===============================================

echo.
echo ^> cargo build (release)
cargo build --release --bin server
if !errorlevel! equ 0 (
    echo   PASSED: cargo build
    set /a PASS+=1
) else (
    echo   FAILED: cargo build
    set FAILURES=!FAILURES! "cargo build"
    set /a FAIL+=1
)

echo.
echo ^> cargo test
cargo test --release
if !errorlevel! equ 0 (
    echo   PASSED: cargo test
    set /a PASS+=1
) else (
    echo   FAILED: cargo test
    set FAILURES=!FAILURES! "cargo test"
    set /a FAIL+=1
)

REM -- Install web dependencies --------------------------------------
echo.
echo ===============================================
echo   Installing npm dependencies
echo ===============================================
pushd web
call npm ci
popd

set PREBUILT_SERVER_BINARY=%cd%\target\release\server.exe

REM -- Detect installed browsers -------------------------------------
set HAS_CHROME=0
set HAS_EDGE=0
set HAS_FIREFOX=0

where chrome >nul 2>&1 && set HAS_CHROME=1
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set HAS_CHROME=1
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set HAS_CHROME=1

where msedge >nul 2>&1 && set HAS_EDGE=1
if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" set HAS_EDGE=1
if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" set HAS_EDGE=1

where firefox >nul 2>&1 && set HAS_FIREFOX=1
if exist "%ProgramFiles%\Mozilla Firefox\firefox.exe" set HAS_FIREFOX=1
if exist "%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe" set HAS_FIREFOX=1

echo.
echo Detected browsers:
echo   Chrome:  %HAS_CHROME%
echo   Edge:    %HAS_EDGE%
echo   Firefox: %HAS_FIREFOX%

REM -- Base browser tests --------------------------------------------
echo.
echo ===============================================
echo   Base browser tests
echo ===============================================

if %HAS_CHROME% equ 1 (
    echo.
    echo ^> Base - Chrome
    call npm run test:chrome
    if !errorlevel! equ 0 (
        echo   PASSED: Base - Chrome
        set /a PASS+=1
    ) else (
        echo   FAILED: Base - Chrome
        set FAILURES=!FAILURES! "Base - Chrome"
        set /a FAIL+=1
    )
) else (
    echo   Skipping Chrome (not found^)
    set /a SKIPPED+=1
)

if %HAS_EDGE% equ 1 (
    echo.
    echo ^> Base - Edge
    call npm run test:edge
    if !errorlevel! equ 0 (
        echo   PASSED: Base - Edge
        set /a PASS+=1
    ) else (
        echo   FAILED: Base - Edge
        set FAILURES=!FAILURES! "Base - Edge"
        set /a FAIL+=1
    )
) else (
    echo   Skipping Edge (not found^)
    set /a SKIPPED+=1
)

if %HAS_FIREFOX% equ 1 (
    echo.
    echo ^> Base - Firefox
    call npm run test:firefox
    if !errorlevel! equ 0 (
        echo   PASSED: Base - Firefox
        set /a PASS+=1
    ) else (
        echo   FAILED: Base - Firefox
        set FAILURES=!FAILURES! "Base - Firefox"
        set /a FAIL+=1
    )
) else (
    echo   Skipping Firefox (not found^)
    set /a SKIPPED+=1
)

REM -- Feature tests (SNAP / SPED / WARP) ---------------------------
echo.
echo ===============================================
echo   Feature tests (SNAP / SPED / WARP)
echo ===============================================

if %HAS_CHROME% equ 1 (
    echo.
    echo ^> SNAP - Chrome
    call npm run test:snap:chrome
    if !errorlevel! equ 0 (
        echo   PASSED: SNAP - Chrome
        set /a PASS+=1
    ) else (
        echo   FAILED: SNAP - Chrome
        set FAILURES=!FAILURES! "SNAP - Chrome"
        set /a FAIL+=1
    )

    echo.
    echo ^> SPED - Chrome
    call npm run test:sped:chrome
    if !errorlevel! equ 0 (
        echo   PASSED: SPED - Chrome
        set /a PASS+=1
    ) else (
        echo   FAILED: SPED - Chrome
        set FAILURES=!FAILURES! "SPED - Chrome"
        set /a FAIL+=1
    )

    echo.
    echo ^> WARP - Chrome
    call npm run test:warp:chrome
    if !errorlevel! equ 0 (
        echo   PASSED: WARP - Chrome
        set /a PASS+=1
    ) else (
        echo   FAILED: WARP - Chrome
        set FAILURES=!FAILURES! "WARP - Chrome"
        set /a FAIL+=1
    )
) else (
    echo   Skipping SNAP/SPED/WARP Chrome (not found^)
    set /a SKIPPED+=3
)

if %HAS_EDGE% equ 1 (
    echo.
    echo ^> SPED - Edge
    call npm run test:sped:edge
    if !errorlevel! equ 0 (
        echo   PASSED: SPED - Edge
        set /a PASS+=1
    ) else (
        echo   FAILED: SPED - Edge
        set FAILURES=!FAILURES! "SPED - Edge"
        set /a FAIL+=1
    )
) else (
    echo   Skipping SPED Edge (not found^)
    set /a SKIPPED+=1
)

REM -- Summary -------------------------------------------------------
echo.
echo ===============================================
echo   Summary
echo ===============================================
echo   Passed:  %PASS%
echo   Failed:  %FAIL%
echo   Skipped: %SKIPPED%

if %FAIL% gtr 0 (
    echo.
    echo Failed tests: %FAILURES%
    exit /b 1
)

echo.
echo All tests passed!
exit /b 0
