#ifndef __SHOWPE_H__
#define __SHOWPE_H__
#include "PEUtil.h"
#include "ShowPE.h"

//打印DosHeader
VOID PrintDosHeaders();

//打印NTHeader
VOID PrintNTHeaders();

//打印PEheader
VOID PrintPEHeaders();

//打印可选的PE头
VOID PrintOptionHeaders();

//打印节表信息
VOID PrintSectionHeaders();




#endif