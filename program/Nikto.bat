@ECHO OFF
title NIKTO
SET /P PRJ="PROJECT_NAME : "
@ECHO +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
@ECHO  OFF                                                                 
@ECHO ++++++     +++    +++++     +++     +++    +++++++++      +++++++
@ECHO +++ +++    +++     +++      +++   +++      +++++++++    ++++   ++++
@ECHO +++  +++   +++     +++      ++++++            +++      ++++     ++++
@ECHO +++   +++  +++     +++      ++++++            +++      ++++     ++++
@ECHO +++    +++ +++     +++      +++   +++         +++       ++++   ++++
@ECHO +++     ++++++    +++++     +++     +++       +++         +++++++
@ECHO OFF                                                                                                      
@ECHO +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
@ECHO RUNNING UPDATE...
@ECHO -----------------------------------
git clone https://github.com/sullo/nikto.git D:\Nikto
cd D:\Nikto
git pull D:\nikto_cpy
cd D:\nikto_cpy
@ECHO -----------------------------------
ECHO SETTING THINGS UP...
@ECHO -----------------------------------
SET FOLDER=%D:\Nikto%
CD /
DEL /F/Q/S "%FOLDER%" > NUL
RMDIR /Q/S "%FOLDER%"
@ECHO Done...
@ECHO -----------------------------------
@ECHO SETTING THINGS RIGHT
@ECHO -----------------------------------

@ECHO Done...

@ECHO -----------------------------------
PAUSE
@ECHO -----------------------------------
SET /P ENTURL="ENTER URL : "
SET /P USRNME="USERNAME : "
SET /P PWD="PASSWORD : "

cd D:\nikto_cpy\program
perl nikto.pl -c all  -Tuning x 6 -o "%PRJ%".html -Format html  -i "%USRNME% "%PWD% "%ENTURL%" -h "%ENTURL%" 
@echo Done Probing...
PAUSE
C:
cd C:\Windows\System32
"cmd /k"
