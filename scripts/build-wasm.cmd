@echo off
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
)
if not exist "%VCVARS%" (
  echo Visual Studio C++ build tools are required to build AuthLens on Windows.
  exit /b 1
)
call "%VCVARS%" >nul
if errorlevel 1 exit /b %ERRORLEVEL%
pushd "%~dp0..\crates\analyzer"
wasm-pack build --target web --out-dir ..\..\web\src\wasm\pkg
set "RESULT=%ERRORLEVEL%"
popd
exit /b %RESULT%
