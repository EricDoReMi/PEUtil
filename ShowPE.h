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

//打印重定位表
VOID PrintRelocationTable(LPVOID pFileBuffer);

//打印导入表
VOID PrintImportTable(LPVOID pFileBuffer);

//打印绑定导入表
VOID PrintBoundImportTable(LPVOID pFileBuffer);

//打印资源表
VOID PrintResourceTable(LPVOID pFileBuffer);

//递归打印资源表的函数
//TableAddr:资源表表头的位置
//pResourceDir
//index:层数
VOID printResource(LPVOID pFileBuffer,DWORD TableAddr,PIMAGE_RESOURCE_DIRECTORY pResourceDir,int index);

//打印names
//index 层数
//names
VOID printIndexTitle(int index,WCHAR* names);

//打印names
//index 层数
//names
VOID printIndexTitle(int index,CHAR* names);

//打印ID
//index 层数
//id
VOID printIndexID(int index,DWORD id);

#endif