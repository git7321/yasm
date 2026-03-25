# Microsoft Developer Studio Project File - Name="re2c" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=re2c - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "re2c.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "re2c.mak" CFG="re2c - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "re2c - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe
# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "."
# PROP BASE Intermediate_Dir "."
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "."
# PROP Intermediate_Dir "."
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
MTL=midl.exe
# ADD BASE MTL /nologo /win32
# ADD MTL /nologo /win32
# ADD BASE CPP /nologo /Gz /MD /W3 /Gy /I "." /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "HAVE_CONFIG_H" /Zc:wchar_t- /Oxs /GF /GS- /c
# ADD CPP /nologo /Gz /MD /W3 /Gy /I "." /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "HAVE_CONFIG_H" /Zc:wchar_t- /Oxs /GF /GS- /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:console /debug /machine:IX86 /opt:ref /opt:icf /release
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:console /debug /machine:IX86 /opt:ref /opt:icf /release
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Cmds=.\re2c -s -o lc3bid.c modules\arch\lc3b\lc3bid.re	.\re2c -b -o nasm-token.c modules\parsers\nasm\nasm-token.re	.\re2c -b -o gas-token.c modules\parsers\gas\gas-token.re
# End Special Build Tool
# Begin Target

# Name "re2c - Win32 Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;def;odl;idl;hpj;bat;asm;asmx"
# Begin Source File

SOURCE=.\tools\re2c\actions.c
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\code.c
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\dfa.c
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\main.c
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\mbo_getopt.c
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\parser.c
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\scanner.c
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\substr.c
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\translate.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;inc;xsd"
# Begin Source File

SOURCE=.\tools\re2c\basics.h
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\dfa.h
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\globals.h
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\ins.h
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\parse.h
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\parser.h
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\re.h
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\scanner.h
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\substr.h
# End Source File
# Begin Source File

SOURCE=.\tools\re2c\token.h
# End Source File
# End Group
# End Target
# End Project
