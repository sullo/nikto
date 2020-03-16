@ECHO OFF
@ECHO +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

@ECHO ++++++     +++    +++++     +++     +++    +++++++++      +++++++
@ECHO +++ +++    +++     +++      +++   +++      +++++++++    ++++   ++++
@ECHO +++  +++   +++     +++      ++++++            +++      ++++     ++++
@ECHO +++   +++  +++     +++      ++++++            +++      ++++     ++++
@ECHO +++    +++ +++     +++      +++   +++         +++       ++++   ++++
@ECHO +++     ++++++    +++++     +++     +++       +++         +++++++

@ECHO +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
@ECHO RUNNING UPDATE...
@ECHO -----------------------------------
git clone https://github.com/sullo/nikto.git D:\Nikto
cd D:\nikto_cpy
git pull
@ECHO -----------------------------------
ECHO SETTING THINGS Right...
@ECHO -----------------------------------
SET FOLDER=%D:\Nikto%
CD /
DEL /F/Q/S "%FOLDER%" > NUL
RMDIR /Q/S "%FOLDER%"

SET /P ENTURL="ENTER URL : "
cd D:\nikto_cpy\program
perl nikto.pl -c all  -Tuning x 6 -o report.html -Format html -h "%ENTURL%"
@echo Done
PAUSE
C:
cd C:\Windows\System32
"cmd /k"
