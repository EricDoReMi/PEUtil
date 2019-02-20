#ifndef __PEUTIL_H__
#define __PEUTIL_H__
#include<memory.h>
#include<Windows.h>
#include<stdio.h>
#include "PEUtil.h"


//获取文件大小
int getFileSize(FILE *P_file);

//读取到FileBuffer
//return 0 失败 1 成功
int InitFileBuffer(LPSTR lpszFile);

//释放FillBuffer
void freePFileBuffer();

//检查是不是PE文件
//return 0 失败 1 成功
int checkIsPEFile();

//获取Dos文件头
PIMAGE_DOS_HEADER getDosHeader();

//获得NT文件头
PIMAGE_NT_HEADERS getNTHeader();


//获得PE文件头
PIMAGE_FILE_HEADER getPEHeader();


//获得可选的PE头
PIMAGE_OPTIONAL_HEADER32 getOptionHeader();

//获得节表头
PIMAGE_SECTION_HEADER getSectionHeader();

#endif
