@echo off
echo Gerando executavel Remove AI Tags...
pip install pyinstaller pillow piexif tkinterdnd2 -q
pyinstaller --onefile --windowed --name "Remove AI Tags by Jair Lima" --clean --hidden-import=piexif --hidden-import=tkinterdnd2 app.py
echo.
if not exist "%USERPROFILE%\bin" mkdir "%USERPROFILE%\bin"
copy "dist\Remove AI Tags by Jair Lima.exe" "%USERPROFILE%\bin\" /Y
echo Pronto! Executavel em: dist\Remove AI Tags by Jair Lima.exe
pause
