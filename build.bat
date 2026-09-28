@echo off
chcp 65001 >nul
echo [NetGuard] Компиляция приложения в среде Windows...
set MSBUILD="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"

if not exist %MSBUILD% (
    echo [ОШИБКА] MSBuild.exe не найден по пути %MSBUILD%
    pause
    exit /b 1
)

%MSBUILD% "%~dp0NetGuard.csproj" /p:Configuration=Release /nologo
if %ERRORLEVEL% equ 0 (
    echo.
    echo =======================================================
    echo [УСПЕХ] NetGuard успешно скомпилирован!
    echo Исполняемый файл: bin\Release\NetGuard.exe
    echo =======================================================
) else (
    echo.
    echo [ОШИБКА] Ошибка при сборке проекта.
)
pause
