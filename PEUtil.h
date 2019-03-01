#ifndef __PEUTIL_H__
#define __PEUTIL_H__
#include<memory.h>
#include<Windows.h>
#include<stdio.h>
#include "PEUtil.h"

//全局变量声明
extern BYTE shellcode[];

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
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区，将ImageBuffer还原为文件的PE格式							
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

//**************************************************************************							
//FileOffsetToRva:将内存偏移转换为文件偏移							
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwFileOffSet RVA的值							
//返回值说明：							
//返回转换后的RVA的值  如果失败返回0							
//**************************************************************************							
DWORD FileOffsetToRva(IN LPVOID pFileBuffer,IN DWORD dwFileOffSet);

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

//获取节表了
//index 第几个节表
//返回值：成功返回该节表头，失败则返回NULL
PIMAGE_SECTION_HEADER getSection(LPVOID pBuffer,WORD index);

//获得节的数量
WORD getSectionNum(LPVOID pBuffer);



//将ShellCode添加到某个Section中
//pathName:源文件路径
//pathNameDes:目标文件路径
//pshellCode:shellCode地址
//shellCodeLength:shellCode的长度
//sectionNum:节的地址了
//返回值:成功返回1,失败返回0
DWORD addShellCodeIntoSection(char* pathName,char* pathNameDes,PBYTE pshellCode,DWORD shellCodeLength,WORD sectionNum);

//判断Section是否足够存储shellCode的代码
//pSectionHeader:要放入代码的section的Header
//shellCodeLength:代码区长度
//返回值:成功则返回1，失败则返回0
DWORD checkSectionHeaderCouldWriteCode(IN PIMAGE_SECTION_HEADER pSectionHeader,DWORD shellCodeLength);

//从ImageBuffer中获得能够注入代码的位置
//返回注入的代码在ImageBuffer中的位置了
PBYTE getCodeBeginFromImageBuffer(IN LPVOID pImageBuffer,IN PIMAGE_SECTION_HEADER pSectionHeader);

//将ImageBuffer中的地址转换为运行时的地址
//pImageBuffer
//imageBufferRunAddr在ImageBuffer中的地址了
//返回运行时的地址
DWORD changeImageBufferAddressToRunTimeAddress(IN LPVOID pImageBuffer,DWORD imageBufferRunAddr);

//将ImageBuffer中的地址转换为E8或E9指令后面跳转的地址的硬编码
//pImageBuffer
//imageBufferRunAddr在ImageBuffer中的地址了
//E8E9RunTimeAddress:E8或E9指令运行时的地址
DWORD changeE8E9AddressFromImageBuffer(IN LPVOID pImageBuffer,DWORD imageBufferRunAddr,DWORD E8E9RunTimeAddress);

//将RunTImeBuffer中的地址转换为E8或E9指令后面跳转的地址的硬编码
//E8E9RunTimeAddress:E8或E9指令运行时的地址
//rumTimeAddress:要转换的运行时地址
//返回：转换后的硬编码地址
DWORD changeE8E9AddressFromRunTimeBuffer(DWORD E8E9RunTimeAddress,DWORD rumTimeAddress);

//获得程序运行时入口的地址
//pBuffer
//返回入口地址
PBYTE getEntryRunTimeAddress(LPVOID pBuffer);

//修改程序运行时入口地址
//pImageBuffer
//imageBufferRunAddress在ImageBuffer中的地址了
void changeEntryPosByImageBufferAddress(LPVOID pImageBuffer,DWORD imageBufferRunAddress);

//修改section的权限
//pBuffer
//sectionNum Section的地址
//characteristics：具体的权限，如0x60000020
//成功，返回1，失败，返回0
DWORD changeSectionCharacteristics(LPVOID pBuffer,WORD sectionNum,DWORD characteristics);

//在pBuffer中将PE的NT头提升到Dos头下
//pBuffer
//返回值:Dos头下的间隙的大小，0:Dos头下没有间隙
DWORD topPENTHeader(IN LPVOID pBuffer);

#endif
