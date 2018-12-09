::UPDATED JULY 2014 v300
::20181021 TLW

echo off
set a32Bit=C:\python32\
set a64Bit=G:\Program Files (x86)\Python36-32\
set a33=C:\python33\
set a34=C:\python34\
set portapython=G:\Portable Python 3.2.5.1\
set winpy=C:\Users\AIODUDE.AIODUDE-PC\Downloads\WinPython64-3.7.0.2\python-3.7.0.amd64\

::if EXIST %a32Bit% (
::"%a32Bit%python3.exe" "%~dp0HBSS_XML_Parser_Driver.py"
) 

::if EXIST %a64Bit% (
::"%a64Bit%python.exe" "%~dp0HBSS_XML_Parser_Driver.py" )

::if EXIST %a34% (
::"%a34%python.exe" "%~dp0HBSS_XML_Parser_Driver.py" )

::if EXIST %a33% (
::"%a33%python.exe" "%~dp0HBSS_XML_Parser_Driver.py" )

::if EXIST %a64Bit% (
::"%a64Bit%python.exe" "%~dp0HIPS_8_FW_XML_Parser.py" CANES-MFOM-POR-SRV_FW_Rules.xml > G:\python\CANES-MFOM-POR-SRV_FW_Rules1.csv
) 

::python3 HIPS_8_FW_XML_Parser.py <HIPS 8 FW XML file to parse>

::if EXIST %portapython% (
::"%portapython%Python-Portable.exe" "%~dp0HBSS_XML_Parser_Driver_Action.py" )

if EXIST %winpy% (
"%winpy%python.exe" "%~dp0HBSS_XML_Parser_Driver_Action.py" )


Pause
