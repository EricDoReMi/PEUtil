#ifndef __SHOWPE_H__
#define __SHOWPE_H__
#include "PEUtil.h"
#include "ShowPE.h"

//打印DosHeader
VOID PrintDosHeaders(LPVOID pFileBuffer);

//打印NTHeader
VOID PrintNTHeaders(LPVOID pFileBuffer);

//打印PEheader
VOID PrintPEHeaders(LPVOID pFileBuffer);

//打印可选的PE头
VOID PrintOptionHeaders(LPVOID pFileBuffer);

//打印节表信息
VOID PrintSectionHeaders(LPVOID pFileBuffer);

//打印目录表
VOID PrintDataDirectory(LPVOID pFileBuffer);

//打印导出表
VOID PrintExportTable(LPVOID pFileBuffer);


#endif