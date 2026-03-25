# Microsoft Developer Studio Project File - Name="modules" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=modules - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "modules.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "modules.mak" CFG="modules - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "modules - Win32 Release" (based on "Win32 (x86) Static Library")
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

# Name "modules - Win32 Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Group "arch"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\modules\arch\lc3b\lc3barch.c
# End Source File
# Begin Source File

SOURCE=.\modules\arch\lc3b\lc3barch.h
# End Source File
# Begin Source File

SOURCE=.\modules\arch\lc3b\lc3bbc.c
# End Source File
# Begin Source File

SOURCE=.\lc3bid.c
# End Source File
# Begin Source File

SOURCE=.\modules\arch\x86\x86arch.c
# End Source File
# Begin Source File

SOURCE=.\modules\arch\x86\x86arch.h
# End Source File
# Begin Source File

SOURCE=.\modules\arch\x86\x86bc.c
# End Source File
# Begin Source File

SOURCE=.\x86cpu.c
# End Source File
# Begin Source File

SOURCE=.\modules\arch\x86\x86expr.c
# End Source File
# Begin Source File

SOURCE=.\modules\arch\x86\x86id.c
# End Source File
# Begin Source File

SOURCE=.\x86regtmod.c
# End Source File
# End Group
# Begin Group "dbgfmts"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\modules\dbgfmts\codeview\cv-dbgfmt.c"
# End Source File
# Begin Source File

SOURCE=".\modules\dbgfmts\codeview\cv-dbgfmt.h"
# End Source File
# Begin Source File

SOURCE=".\modules\dbgfmts\codeview\cv-symline.c"
# End Source File
# Begin Source File

SOURCE=".\modules\dbgfmts\codeview\cv-type.c"
# End Source File
# Begin Source File

SOURCE=".\modules\dbgfmts\dwarf2\dwarf2-aranges.c"
# End Source File
# Begin Source File

SOURCE=".\modules\dbgfmts\dwarf2\dwarf2-dbgfmt.c"
# End Source File
# Begin Source File

SOURCE=".\modules\dbgfmts\dwarf2\dwarf2-dbgfmt.h"
# End Source File
# Begin Source File

SOURCE=".\modules\dbgfmts\dwarf2\dwarf2-info.c"
# End Source File
# Begin Source File

SOURCE=".\modules\dbgfmts\dwarf2\dwarf2-line.c"
# End Source File
# Begin Source File

SOURCE=".\modules\dbgfmts\null\null-dbgfmt.c"
# End Source File
# Begin Source File

SOURCE=".\modules\dbgfmts\stabs\stabs-dbgfmt.c"
# End Source File
# End Group
# Begin Group "objfmts"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\modules\objfmts\bin\bin-objfmt.c"
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\coff\coff-objfmt.c"
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\coff\coff-objfmt.h"
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\dbg\dbg-objfmt.c"
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\elf\elf-machine.h"
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\elf\elf-objfmt.c"
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\elf\elf-x86-amd64.c"
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\elf\elf-x86-x32.c"
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\elf\elf-x86-x86.c"
# End Source File
# Begin Source File

SOURCE=.\modules\objfmts\elf\elf.c
# End Source File
# Begin Source File

SOURCE=.\modules\objfmts\elf\elf.h
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\macho\macho-objfmt.c"
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\rdf\rdf-objfmt.c"
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\coff\win64-except.c"
# End Source File
# Begin Source File

SOURCE=".\modules\objfmts\xdf\xdf-objfmt.c"
# End Source File
# End Group
# Begin Group "parsers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\modules\parsers\gas\gas-parse-intel.c"
# End Source File
# Begin Source File

SOURCE=".\modules\parsers\gas\gas-parse.c"
# End Source File
# Begin Source File

SOURCE=".\modules\parsers\gas\gas-parser.c"
# End Source File
# Begin Source File

SOURCE=".\modules\parsers\gas\gas-parser.h"
# End Source File
# Begin Source File

SOURCE=".\gas-token.c"
# End Source File
# Begin Source File

SOURCE=".\modules\parsers\nasm\nasm-parse.c"
# End Source File
# Begin Source File

SOURCE=".\modules\parsers\nasm\nasm-parser.c"
# End Source File
# Begin Source File

SOURCE=".\modules\parsers\nasm\nasm-parser.h"
# End Source File
# Begin Source File

SOURCE=".\nasm-token.c"
# End Source File
# End Group
# Begin Group "preprocs"

# PROP Default_Filter ""
# Begin Group "nasm"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\modules\preprocs\nasm\nasm-eval.c"
# End Source File
# Begin Source File

SOURCE=".\modules\preprocs\nasm\nasm-eval.h"
# End Source File
# Begin Source File

SOURCE=".\modules\preprocs\nasm\nasm-pp.c"
# End Source File
# Begin Source File

SOURCE=".\modules\preprocs\nasm\nasm-pp.h"
# End Source File
# Begin Source File

SOURCE=".\modules\preprocs\nasm\nasm-preproc.c"
# End Source File
# Begin Source File

SOURCE=.\modules\preprocs\nasm\nasm.h
# End Source File
# Begin Source File

SOURCE=.\modules\preprocs\nasm\nasmlib.c
# End Source File
# Begin Source File

SOURCE=.\modules\preprocs\nasm\nasmlib.h
# End Source File
# End Group
# Begin Group "raw"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\modules\preprocs\raw\raw-preproc.c"
# End Source File
# End Group
# Begin Group "cpp"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\modules\preprocs\cpp\cpp-preproc.c"
# End Source File
# End Group
# Begin Group "gas"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\modules\preprocs\gas\gas-eval.c"
# End Source File
# Begin Source File

SOURCE=".\modules\preprocs\gas\gas-eval.h"
# End Source File
# Begin Source File

SOURCE=".\modules\preprocs\gas\gas-preproc.c"
# End Source File
# End Group
# End Group
# Begin Group "listfmts"

# PROP Default_Filter ""
# Begin Group "nasm No. 1"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\modules\listfmts\nasm\nasm-listfmt.c"
# End Source File
# End Group
# End Group
# End Group
# End Target
# End Project
