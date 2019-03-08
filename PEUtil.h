#ifndef __PEUTIL_H__
#define __PEUTIL_H__
#include "Common.h"
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
//RvaToSectionIndex:通过内存偏移寻找sectionIndex						
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwRva RVA的值							
//返回值说明：							
//返回找到的SectionNum号 如果失败返回0							
//**************************************************************************							
DWORD RvaToSectionIndex(IN LPVOID pFileBuffer,IN DWORD dwRva);

//**************************************************************************							
//FileOffsetToRva:将文件偏移转换为内存偏移							
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwFileOffSet RVA的值							
//返回值说明：							
//返回转换后的RVA的值  如果失败返回0							
//**************************************************************************							
DWORD FileOffsetToRva(IN LPVOID pFileBuffer,IN DWORD dwFileOffSet);


//**************************************************************************							
//RvaToFileBufferAddress:将内存偏移转换为FileBuffer中的地址了							
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwRva RVA的值							
//返回值说明：							
//返回转换后的FileAddress的值  如果失败返回0							
//**************************************************************************							
DWORD RvaToFileBufferAddress(IN LPVOID pFileBuffer,IN DWORD dwRva);

//**************************************************************************							
//FileBufferAddressToRva:将FileBuffer中的地址转换为内存偏移							
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwFileAddress fileBuffer中地址						
//返回值说明：							
//返回转换后的RVA的值  如果失败返回0							
//**************************************************************************							
DWORD FileBufferAddressToRva(IN LPVOID pFileBuffer,IN DWORD dwFileAddress);
	

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

//在pBuffer中将PE的NT头和Section表头提升到Dos头下
//pBuffer
//返回值:Dos头下的间隙的大小，0:Dos头下没有间隙
DWORD topPENTAndSectionHeader(IN LPVOID pBuffer);

//获得节表的最后一个字节的下一个字节的地址
//pBuffer
//返回值:LPVOID,还是一个节表指针，用于新增节表
LPVOID getSectionEnderNext(IN LPVOID pBuffer);

//判断是否可以添加一个节表,若最后一个节表有80个字节全为0,则可以添加
//pBuffer
//返回值:1成功,0失败
DWORD checkCanAddSection(IN LPVOID pBuffer);

//新增一个节表,权限为
//pBuffer
//sizeOfNewSection,新增的节表占多少
//pNewBuffer返回成功后newBuffer地址
//characteristics：具体的权限，如0x60000020
//返回值 1成功 0失败
DWORD addNewSection(IN LPVOID pImageBuffer,DWORD sizeOfNewSection,DWORD characteristics,OUT LPVOID* pNewImageBuffer);

//获得FileBuffer的大小
DWORD getFileBufferSize(IN LPVOID pFileBuffer);


//直接在FileBuffer中新增一个节
//pFileBuffer
//sizeOfNewSection,新增的字节数
//pNewFileBuffer返回成功后newFileBuffer地址
//characteristics：具体的权限，如0x60000020
//返回值 返回新增节首地址的RVA 0失败
DWORD addNewSectionByFileBuffer(IN LPVOID pFileBuffer,DWORD sizeOfNewSection,DWORD characteristics,OUT LPVOID* pNewFileBuffer);


//扩展最后一个节表
//pBuffer
//addSize,增加的字节数
//pNewBuffer返回成功后newBuffer地址
//characteristics：具体的权限，如0x60000020
//返回值 1成功 0失败
DWORD extendTheLastSection(IN LPVOID pImageBuffer,DWORD addSizeNew,DWORD characteristics,OUT LPVOID* pNewImageBuffer);

//按fileBuffer扩展最后一个节表
//pBuffer
//addSize,增加的字节数
//pNewBuffer返回成功后newBuffer地址
//characteristics：具体的权限，如0x60000020
//返回值 1成功 0失败
DWORD extendTheLastSectionByFileBuffer(IN LPVOID pFileBuffer,DWORD addSizeNew,DWORD characteristics,OUT LPVOID* pNewFileBuffer);

//合并所有节
//pBuffer
//characteristics 合并后只有一个节，要运行，可设置权限为0xE0000020，若还要增加其他节，可设置其他权限，但无法运行
//pNewBuffer返回成功后newBuffer地址
//返回值 1成功 0失败
DWORD mergeAllSections(IN LPVOID pImageBuffer,DWORD characteristics,OUT LPVOID* pNewImageBuffer);

//将changeNumber改为baseNumber的整数倍
DWORD changeNumberByBase(DWORD baseNumber,DWORD changeNumber);


//===================PIMAGE_DATA_DIRECTORY=======================
//按index获取DataDirectoryTable信息
//pFileBuffer
//index 序号,如 1 导出表
//返回 PIMAGE_DATA_DIRECTORY
PIMAGE_DATA_DIRECTORY getDataDirectory(LPVOID pFileBuffer,DWORD index);


//********************导出表********************************
//通过导出表函数名获得函数地址RVA
//pFileBuffer
//pFunName 函数名字符串指针
//返回值:成功 该函数RVA
DWORD GetFunctionRVAByName(LPVOID pFileBuffer,char* pFunName);

//通过导出表函数序号获得函数地址RVA,序号来自于.def文件中的定义
//pFileBuffer
//index 序号
//返回值:成功 该函数RVA
DWORD GetFunctionRVAByOrdinals(LPVOID pFileBuffer,DWORD index);

//获取导出表的大小,包括导出表中的函数地址表，函数名称表和函数序号表的大小，以及函数名称表所指向的字符串的大小
//pFileBuffer
//返回值 导出表大小
DWORD getExportDirectorySize(LPVOID pFileBuffer);

//移动导出表
//pFileBuffer
//fileRVA 导出表被移动到的RVA
void removeExportDirectory(LPVOID pFileBuffer,DWORD fileRVA);

//获取重定位表的大小
//pFileBuffer
//返回值 重定位表的大小
DWORD getRelocationDirectorySize(LPVOID pFileBuffer);

//移动重定位表
//pFileBuffer
//fileRVA 导出表被移动到的RVA
void removeRelocationDirectory(LPVOID pFileBuffer,DWORD fileRVA);

//******************************ImportTableDirectory******************************
//获取导入表所有结构体的大小
//pFileBuffer
//返回值 导入表的大小
DWORD getImageImportDescriptorsSize(LPVOID pFileBuffer);

//获得Dll文件的信息
//pFileInputPath 文件的路径
//pFunName 导入表函数名
//pDllNames,输出Dll文件的名字
//返回 添加到PE导入表中的需要分配的大小
DWORD getDllExportInfor(IN char* pFileInputPath,char* pFunName,char** pDllName);

//移动导入表
//pFileBuffer
//fileRVA 
//imageImportDescriptorsSize,要移动的导入表的大小
//返回 移动后新导入表末尾的下一个字节地址
DWORD removeImportDirectory(LPVOID pFileBuffer,DWORD fileRVA,DWORD imageImportDescriptorsSize);

#endif
