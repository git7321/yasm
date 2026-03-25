# Microsoft Developer Studio Project File - Name="libyasm" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libyasm - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libyasm.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libyasm.mak" CFG="libyasm - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libyasm - Win32 Release" (based on "Win32 (x86) Static Library")
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
# PROP Target_Dir ""
MTL=midl.exe
# ADD BASE MTL /nologo /win32
# ADD MTL /nologo /win32
# ADD BASE CPP /nologo /Gz /MD /W3 /Gy /I "." /D "NDEBUG" /D "WIN32" /D "_LIB" /D "_MBCS" /D "HAVE_CONFIG_H" /Zc:wchar_t- /Oxs /GF /GS- /c
# ADD CPP /nologo /Gz /MD /W3 /Gy /I "." /D "NDEBUG" /D "WIN32" /D "_LIB" /D "_MBCS" /D "HAVE_CONFIG_H" /Zc:wchar_t- /Oxs /GF /GS- /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo
# Begin Target

# Name "libyasm - Win32 Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\libyasm\assocdat.c
# End Source File
# Begin Source File

SOURCE=".\libyasm\bc-align.c"
# End Source File
# Begin Source File

SOURCE=".\libyasm\bc-data.c"
# End Source File
# Begin Source File

SOURCE=".\libyasm\bc-incbin.c"
# End Source File
# Begin Source File

SOURCE=".\libyasm\bc-org.c"
# End Source File
# Begin Source File

SOURCE=".\libyasm\bc-reserve.c"
# End Source File
# Begin Source File

SOURCE=.\libyasm\bitvect.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\bytecode.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\errwarn.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\expr.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\file.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\file.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\floatnum.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\hamt.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\insn.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\intnum.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\inttree.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\linemap.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\md5.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\mergesort.c
# End Source File
# Begin Source File

SOURCE=.\module.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\phash.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\section.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\strcasecmp.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\strsep.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\symrec.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\valparam.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\value.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\xmalloc.c
# End Source File
# Begin Source File

SOURCE=.\libyasm\xstrdup.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\libyasm\arch.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\assocdat.h
# End Source File
# Begin Source File

SOURCE=".\libyasm\bc-int.h"
# End Source File
# Begin Source File

SOURCE=.\libyasm\bitvect.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\bytecode.h
# End Source File
# Begin Source File

SOURCE=".\libyasm\compat-queue.h"
# End Source File
# Begin Source File

SOURCE=.\config.h
# Begin Custom Build
IntDir=.\.
InputPath=config.h
InputName="yasm-version"

"$(IntDir)/(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	set /p _ver_=<$(IntDir)/version 
	echo #define PACKAGE_STRING "yasm %_ver_%" > "$(IntDir)/yasm-version.h" 
	echo #define PACKAGE_VERSION "%_ver_%" >> "$(IntDir)/yasm-version.h" 
	
# End Custom Build
# End Source File
# Begin Source File

SOURCE=".\yasm-version.h"
# End Source File
# Begin Source File

SOURCE=.\libyasm\coretype.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\dbgfmt.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\errwarn.h
# End Source File
# Begin Source File

SOURCE=".\libyasm\expr-int.h"
# End Source File
# Begin Source File

SOURCE=.\libyasm\expr.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\floatnum.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\hamt.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\insn.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\intnum.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\inttree.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\linemap.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\md5.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\objfmt.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\parser.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\phash.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\preproc.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\section.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\symrec.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\util.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\valparam.h
# End Source File
# Begin Source File

SOURCE=.\libyasm\value.h
# End Source File
# End Group
# Begin Source File

SOURCE=.\libyasm\module.in
# End Source File
# End Target
# End Project
