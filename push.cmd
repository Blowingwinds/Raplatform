@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

where git >nul 2>&1
if errorlevel 1 goto :missing_git

set "repoRoot="
for /f "delims=" %%R in ('git rev-parse --show-toplevel 2^>nul') do set "repoRoot=%%R"
if not defined repoRoot goto :not_repo
cd /d "%repoRoot%"

set "branch="
for /f "delims=" %%B in ('git symbolic-ref --quiet --short HEAD 2^>nul') do set "branch=%%B"
if not defined branch goto :detached_head

set "remoteUrl="
for /f "delims=" %%U in ('git remote get-url origin 2^>nul') do set "remoteUrl=%%U"
if not defined remoteUrl goto :missing_remote

set "commitMessage="
set /p "commitMessage=Commit message (press Enter for automatic): "
if not defined commitMessage set "commitMessage=Update project %date% %time:~0,8%"

echo.
echo Repository: %repoRoot%
echo Branch:     %branch%
echo Remote:     %remoteUrl%
echo.

git add --all
if errorlevel 1 goto :git_error

git diff --cached --quiet
if errorlevel 2 goto :git_error
if errorlevel 1 goto :commit_changes
echo No new file changes to commit.
goto :sync_remote

:commit_changes
git commit -m "%commitMessage%"
if errorlevel 1 goto :git_error

:sync_remote
git ls-remote --exit-code --heads origin "%branch%" >nul 2>&1
if errorlevel 128 goto :git_error
if errorlevel 2 goto :push_changes
if errorlevel 1 goto :git_error

git pull --rebase origin "%branch%"
if errorlevel 1 goto :git_error

:push_changes
git push --set-upstream origin "%branch%"
if errorlevel 1 goto :git_error

echo.
echo Push completed for origin/%branch%.
exit /b 0

:missing_git
echo Error: Git was not found on PATH.
exit /b 1

:not_repo
echo Error: The current directory is not inside a Git repository.
exit /b 1

:detached_head
echo Error: The repository is in detached HEAD state.
exit /b 1

:missing_remote
echo Error: Remote "origin" is not configured.
exit /b 1

:git_error
echo Error: Git command failed. Resolve the error above and run push.cmd again.
exit /b 1
