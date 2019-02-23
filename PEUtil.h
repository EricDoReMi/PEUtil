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
//函数声明							
//**************************************************************************							
//ReadPEFile:将文件读取到缓冲区							
//参数说明：							
//lpszFile 文件路径							
//pFileBuffer 缓冲区指针							
//返回值说明：							
//读取失败返回0  否则返回实际读取的大小							
//**************************************************************************							
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);

//**************************************************************************							
//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer							
//参数说明：							
//pFileBuffer  FileBuffer指针							
//pImageBuffer ImageBuffer指针							
//返回值说明：							
//读取失败返回0  否则返回复制的大小							
//**************************************************************************
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);
//**************************************************************************							
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区							
//参数说明：							
//pImageBuffer ImageBuffer指针							
//pNewBuffer NewBuffer指针							
//返回值说明：							
//读取失败返回0  否则返回复制的大小							
//**************************************************************************							
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);
//**************************************************************************							
//MemeryTOFile:将内存中的数据复制到文件							
//参数说明：							
//pMemBuffer 内存中数据的指针							
//size 要复制的大小							
//lpszFile 要存储的文件路径							
//返回值说明：							
//读取失败返回0  否则返回复制的大小							
//**************************************************************************							
DWORD MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);
//**************************************************************************							
//RvaToFileOffset:将内存偏移转换为文件偏移							
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwRva RVA的值							
//返回值说明：							
//返回转换后的FOA的值  如果失败返回0							
//**************************************************************************							
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);

//释放Buffer
void freePBuffer(LPVOID pBuffer);

//检查是不是PE文件
//return 0 失败 1 成功
int checkIsPEFile(LPVOID pBuffer);

//获取Dos文件头
PIMAGE_DOS_HEADER getDosHeader(LPVOID pBuffer);

//获得NT文件头
PIMAGE_NT_HEADERS getNTHeader(LPVOID pBuffer);


//获得PE文件头
PIMAGE_FILE_HEADER getPEHeader(LPVOID pBuffer);


//获得可选的PE头
PIMAGE_OPTIONAL_HEADER32 getOptionHeader(LPVOID pBuffer);

//获得节表头
PIMAGE_SECTION_HEADER getSectionHeader(LPVOID pBuffer);

//获得节的数量
WORD getSectionNum(LPVOID pBuffer);

//获取节表了
//index 第几个节表
PIMAGE_SECTION_HEADER getSection(LPVOID pBuffer,WORD index);

#endif
