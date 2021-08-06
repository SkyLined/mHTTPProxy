@ECHO OFF
SETLOCAL
IF EXIST "%~dpn0\%~n0\%~nx0" (
  CALL "%~dpn0\%~n0\%~nx0" %*
)
SET TEST_ALL=FALSE
SET TEST_PYTHON=MAYBE
SET TEST_PHP=MAYBE
SET TEST_JAVASCRIPT=MAYBE
CALL :PARSE_ARGUMENTS %*

IF NOT "%TEST_PYTHON%" == "FALSE" (
  IF NOT EXIST "%~dp0\%~n0\%~n0.py" (
    IF NOT "%TEST_PYTHON%" == "MAYBE" (
      ECHO - There is no file "%~dp0\%~n0\%~n0.py" for testing!
    )
  ) ELSE (
    CALL :TEST_PYTHON %*
    IF ERRORLEVEL 1 GOTO :ERROR
  )
)
IF NOT "%TEST_PHP%" == "FALSE" (
  IF NOT EXIST "%~dp0\%~n0\%~n0.php" (
    IF NOT "%TEST_PHP%" == "MAYBE" (
      ECHO - There is no file "%~dp0\%~n0\%~n0.php" for testing!
    )
  ) ELSE (
    CALL :TEST_PHP %*
    IF ERRORLEVEL 1 GOTO :ERROR
  )
)
IF NOT "%TEST_JAVASCRIPT%" == "FALSE" (
  IF NOT EXIST "%~dp0\%~n0\%~n0.js" (
    IF NOT "%TEST_JAVASCRIPT%" == "MAYBE" (
      ECHO - There is no file "%~dp0\%~n0\%~n0.js" for testing!
    )
  ) ELSE (
    CALL :TEST_JAVASCRIPT %*
    IF ERRORLEVEL 1 GOTO :ERROR
  )
)

:PARSE_ARGUMENTS
  IF "%~1" == "--all" (
    SET TEST_ALL=TRUE
  ) ELSE IF "%~1" == "--python" (
    SET TEST_PYTHON=TRUE
  ) ELSE IF "%~1" == "--php" (
    SET TEST_PHP=TRUE
  ) ELSE IF "%~1" == "--javascript" (
    SET TEST_JAVASCRIPT=TRUE
  )
  SHIFT
  IF NOT "%~1" == "" GOTO :PARSE_ARGUMENTS
  IF "%TEST_PYTHON%" == "MAYBE" IF "%TEST_PHP%" == "MAYBE" IF "%TEST_JAVASCRIPT%" == "MAYBE" (
    REM The user did not pick a specific language to test, so test all of them:
    EXIT /B 0
  )
  REM The user picked one or more specific languages to test, so do not test those that they did not select:
  IF "%TEST_PYTHON%" == "MAYBE" SET TEST_PYTHON=FALSE
  IF "%TEST_PHP%" == "MAYBE" SET TEST_PHP=FALSE
  IF "%TEST_JAVASCRIPT%" == "MAYBE" SET TEST_JAVASCRIPT=FALSE
  EXIT /B 0
  

:TEST_PYTHON
  IF "%TEST_ALL%" == "TRUE" (
    REM If you can add the x86 and x64 binaries of python to the path, or add links to the local folder, tests will be run
    REM in both
    WHERE PYTHON_X86 >nul 2>&1
    IF NOT ERRORLEVEL 0 (
      ECHO - PYTHON_X86 was not found; not testing both x86 and x64 ISAs.
    ) ELSE (
      WHERE PYTHON_X64 >nul 2>&1
      IF NOT ERRORLEVEL 0 (
        ECHO - PYTHON_X64 was not found; not testing both x86 and x64 ISAs.
      ) ELSE (
        GOTO :RUN_PYTHON_FOR_BOTH_ISAS
      )
    )
  )

  IF DEFINED PYTHON (
    CALL :CHECK_PYTHON
    IF NOT ERRORLEVEL 1 GOTO :RUN_PYTHON
  )
  REM Try to detect the location of python automatically
  FOR /F "usebackq delims=" %%I IN (`where "python" 2^>nul`) DO (
    SET PYTHON="%%~fI"
    CALL :CHECK_PYTHON
    IF NOT ERRORLEVEL 1 GOTO :RUN_PYTHON
  )
  REM Check if python is found in its default installation path.
  FOR /D %%I IN ("%LOCALAPPDATA%\Programs\Python\*") DO (
    SET PYTHON="%%~fI\python.exe"
    CALL :CHECK_PYTHON
    IF NOT ERRORLEVEL 1 GOTO :RUN_PYTHON
  )
  IF "%TEST_PYTHON%" == "MAYBE" EXIT /B 0
  ECHO - Cannot find python.exe. Please set the "PYTHON" environment variable to the
  ECHO   correct path, or add Python to the "PATH" environment variable.
  EXIT /B 1

:CHECK_PYTHON
  REM Make sure path is quoted and check if it exists.
  SET PYTHON="%PYTHON:"=%"
  IF NOT EXIST %PYTHON% EXIT /B 1
  EXIT /B 0

:RUN_PYTHON
  CALL %PYTHON% "%~dpn0\%~n0.py" %*
  IF ERRORLEVEL 1 (
    ECHO   - Failed with error %ERRORLEVEL%!
    ENDLOCAL
    EXIT /B %ERRORLEVEL%
  )
  ECHO + Done.
  ENDLOCAL
  EXIT /B 0

:RUN_PYTHON_FOR_BOTH_ISAS
  ECHO + Testing using Python for x86 ISA...
  CALL %PYTHON_X86% "%~dpn0\%~n0.py" %*
  IF NOT ERRORLEVEL 1 (
    ECHO + Testing using Python for x64 ISA...
    CALL %PYTHON_X64% "%~dpn0\%~n0.py" %*
  )
  IF ERRORLEVEL 1 (
    ECHO   - Failed with error %ERRORLEVEL%!
    ENDLOCAL
    EXIT /B %ERRORLEVEL%
  )
  ECHO + Done.
  ENDLOCAL
  EXIT /B 0

:TEST_PHP
  SETLOCAL
  IF NOT DEFINED PHP (
    REM Try to detect the location of PHP automatically
    FOR /F "usebackq delims=" %%I IN (`where "php" 2^>nul`) DO (
      SET PHP="%%~I"
      GOTO :FOUND_PHP
    )
    ECHO - Cannot find php.exe. Please add PHP to the "PATH" environment variable.
    ENDLOCAL
    IF "%TEST_PHP%" == "MAYBE" EXIT /B 0
    EXIT /B 1
  )
:FOUND_PHP
  ECHO * Testing PHP...
  CALL %PHP% "%~dp0\%~n0\%~n0.php" %*
  ENDLOCAL & EXIT /B %ERRORLEVEL%

:TEST_NODE
  REM CURRENTLY NOT IMPLEMENTED - You can load the Tests.html file in a browser
  REM to test the JavaScript implementation
  ECHO * Testing NODE not implemented yet.
  EXIT /B 0
  IF NOT DEFINED NODE (
    REM Try to detect the location of PHP automatically
    FOR /F "usebackq delims=" %%I IN (`where "node" 2^>nul`) DO (
      SET NODE="%%~I"
      GOTO :FOUND_NODE
    )
    ECHO - Cannot find node.exe. Please add Node to the "PATH" environment variable.
    ENDLOCAL
    IF "%TEST_PHP%" == "MAYBE" EXIT /B 0
    EXIT /B 1
  )
:FOUND_NODE
  ECHO * Testing NODE...
  CALL %NODE% "%~dp0\Tests\Tests.js" %*
  ENDLOCAL & EXIT /B %ERRORLEVEL%

:ERROR
  ECHO - Error %ERRORLEVEL%!
  EXIT /B %ERRORLEVEL%