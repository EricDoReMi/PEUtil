#include "PEUtil.h"


//获取文件大小
int getFileSize(FILE *P_file){
	int filesize=0;
	if(P_file){
		fseek(P_file,0,SEEK_END);
		filesize=ftell(P_file);
		fseek(P_file, 0, SEEK_SET);
	}else{
		printf("getFileSize Failed---文件指针为NULL");
	}
	return filesize;
}

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
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer)		
{		
	FILE *pFile = NULL;	
	DWORD fileSize = 0;	
	LPVOID pFileBufferTmp=NULL;
		
	//打开文件	
    pFile = fopen(lpszFile, "rb");		
	if(!pFile)	
	{	
		printf("ReadPEFile Failed---无法打开EXE 文件,%s!\n",lpszFile);
		return 0;
	}	
    //读取文件大小		

    fileSize = getFileSize(pFile);		

	//分配缓冲区	
	pFileBufferTmp = malloc(fileSize);	
		
	if(!pFileBufferTmp)	
	{	
		printf("ReadPEFile  Failed---读取PE文件后分配空间失败%s!\n",lpszFile);
		fclose(pFile);
		pFile=NULL;
		pFileBufferTmp=NULL;
		return 0;
	}	

	memset(pFileBufferTmp,0,fileSize);

	//将文件数据读取到缓冲区	
	size_t n = fread(pFileBufferTmp, 1, fileSize, pFile);	
	if(!n)	
	{	
		printf("ReadPEFile Failed---读取PE文件数据失败,%s!\n",lpszFile);
		free(pFileBufferTmp);
		fclose(pFile);
		pFile=NULL;
		pFileBufferTmp=NULL;
		return 0;
	}	

	if(!checkIsPEFile(pFileBufferTmp)){
		printf("ReadPEFile Failed---不是标准PE文件,%s!\n",lpszFile);
		free(pFileBufferTmp);
		fclose(pFile);
		pFile=NULL;
		pFileBufferTmp=NULL;
		return 0;
	}
	//关闭文件	
	fclose(pFile);
	pFile=NULL;
	*pFileBuffer=pFileBufferTmp;
	printf("ReadPEFile successed,%s!\n",lpszFile);
    return (DWORD)n;		
	
}

//**************************************************************************							
//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer							
//参数说明：							
//pFileBuffer  FileBuffer指针							
//pImageBuffer ImageBuffer指针							
//返回值说明：							
//读取失败返回0  否则返回复制的大小							
//**************************************************************************
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer){
	if(!checkIsPEFile(pFileBuffer)){
		printf("CopyFileBufferToImageBuffer Failed---pFileBuffer不是标准PE文件!\n");
		free(pFileBuffer);
	
		pFileBuffer=NULL;
		return 0;
	}

	LPVOID pImageBufferTmp=NULL;
	PIMAGE_OPTIONAL_HEADER32 POptionPEHeader=getOptionHeader(pFileBuffer);
	DWORD sizeOfImage=POptionPEHeader->SizeOfImage;
	DWORD sizeOfHeaders=POptionPEHeader->SizeOfHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);
	WORD sectionNum=getSectionNum(pFileBuffer);
	
	pImageBufferTmp=malloc(sizeOfImage);
	if(!pImageBufferTmp)	
	{	
		printf("malloc PImageBuffer失败! ");
		
		return 0;
	}
	
	memset(pImageBufferTmp,0,sizeOfImage);

	//============将pFileBuffer数据读取到pImageBuffer中=========

	//读取Headers

	memcpy(pImageBufferTmp,pFileBuffer,POptionPEHeader->SizeOfHeaders);

	DWORD virtualAddress=0;
	DWORD sizeOfRawData=0;
	DWORD pointerToRawData=0;

	
	//根据节表中的信息循环将FileBuffer中的节拷贝到ImageBuffer中
	DWORD i=0;
	for(i=0;i<sectionNum;i++)
	{
		virtualAddress=pSectionHeader->VirtualAddress;
		sizeOfRawData=pSectionHeader->SizeOfRawData;
		pointerToRawData=pSectionHeader->PointerToRawData;
		DWORD j=0;
		for(j=0;j<sizeOfRawData;j++){
			*((char*)pImageBufferTmp+virtualAddress+j)=*((char*)pFileBuffer+pointerToRawData+j);
		}
		
		pSectionHeader=(PIMAGE_SECTION_HEADER)((char*)pSectionHeader+40);

	}

	*pImageBuffer=pImageBufferTmp;

	return sizeOfImage;
}							
//**************************************************************************							
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区，将ImageBuffer还原为文件的PE格式							
//参数说明：							
//pImageBuffer ImageBuffer指针							
//pNewBuffer NewBuffer指针							
//返回值说明：							
//读取失败返回0  否则返回复制的大小							
//**************************************************************************							
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer){
	if(!checkIsPEFile(pImageBuffer)){
		printf("CopyImageBufferToNewBuffer Failed---pImageBuffer不是标准PE文件!\n");
		free(pImageBuffer);
	
		pImageBuffer=NULL;
		return 0;
	}
	LPVOID pNewBufferTmp=NULL;
	PIMAGE_OPTIONAL_HEADER32 POptionPEHeader=getOptionHeader(pImageBuffer);
	DWORD sizeOfHeaders=POptionPEHeader->SizeOfHeaders;
	
	WORD sectionNum=getSectionNum(pImageBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader=getSection(pImageBuffer,sectionNum);
	char arr[9]={0};
	char* p_arr=arr;
	p_arr=(char*)pLastSectionHeader->Name;
	printf("%s\n",p_arr);
	DWORD pointerToRawDataLastSection=pLastSectionHeader->PointerToRawData;
	DWORD sizeOfRawDataLastSection=pLastSectionHeader->SizeOfRawData;
	DWORD sizeOfNewBuffer=pointerToRawDataLastSection+sizeOfRawDataLastSection;
	

	pNewBufferTmp=malloc(sizeOfNewBuffer);
	if(!pNewBufferTmp)	
	{	
		printf("malloc pNewBufferTmp失败! ");
		
		return 0;
	}
	
	memset(pNewBufferTmp,0,sizeOfNewBuffer);
	
	//============将pImageBuffer数据读取到pNewBuffer中=========
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pImageBuffer);
	DWORD i=0;
	//读取Headers
	for(i=0;i<sizeOfHeaders;i++)
	{
		*((char*)pNewBufferTmp+i)=*((char*)pImageBuffer+i);
	}

	DWORD virtualAddress=0;
	DWORD sizeOfRawData=0;
	DWORD pointerToRawData=0;


	//根据节表中的信息循环将pImageBuffer中的节拷贝到pNewBuffer中
	for(i=0;i<sectionNum;i++)
	{
		virtualAddress=pSectionHeader->VirtualAddress;
		sizeOfRawData=pSectionHeader->SizeOfRawData;
		pointerToRawData=pSectionHeader->PointerToRawData;
		DWORD j=0;
		for(j=0;j<sizeOfRawData;j++){
			*((char*)pNewBufferTmp+pointerToRawData+j)=*((char*)pImageBuffer+virtualAddress+j);
		}
		
		pSectionHeader=(PIMAGE_SECTION_HEADER)((char*)pSectionHeader+40);

	}

	*pNewBuffer=pNewBufferTmp;

	return sizeOfNewBuffer;
}							
//**************************************************************************							
//MemeryTOFile:将内存中的数据复制到文件							
//参数说明：							
//pMemBuffer 内存中数据的指针							
//size 要复制的大小							
//lpszFile 要存储的文件路径							
//返回值说明：							
//读取失败返回0  否则返回复制的大小							
//**************************************************************************							
DWORD MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile){
	if(!checkIsPEFile(pMemBuffer)){
		printf("CopyImageBufferToNewBuffer Failed---pMemBuffer不是标准PE文件,%s!\n",lpszFile);
		free(pMemBuffer);
		pMemBuffer=NULL;
		return 0;
	}
	FILE *p_file=NULL;
	p_file=fopen(lpszFile,"wb");
	if(p_file){
		DWORD writeSize=(DWORD)fwrite(pMemBuffer,size,1,p_file);
		
		fclose(p_file);
		p_file=NULL;
		
		return writeSize;
	}
		return 0;
		
}							
//**************************************************************************							
//RvaToFileOffset:将内存偏移转换为文件偏移							
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwRva RVA的值							
//返回值说明：							
//返回转换后的FOA的值  如果失败返回0							
//**************************************************************************							
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva){
	return 0;
}

//释放Buffer
void freePBuffer(LPVOID pBuffer){
	
	if(pBuffer){
		free(pBuffer);
		pBuffer=NULL;
	}
}

//检查是不是PE文件
//return 0 失败 1 成功
int checkIsPEFile(LPVOID pBuffer){
		//判断是否是有效的MZ标志	
	if(*((PWORD)pBuffer) != IMAGE_DOS_SIGNATURE)	
	{	
		printf("不是有效的MZ标志\n");
		freePBuffer(pBuffer);
		return 0; 
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pBuffer);
		//判断是否是有效的PE标志	
	if(*((PDWORD)((DWORD)pBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)	
	{	
		printf("不是有效的PE标志\n");
		free(pBuffer);
		return 0;
	}

	return 1;
}

//获取Dos文件头
PIMAGE_DOS_HEADER getDosHeader(LPVOID pBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	return pDosHeader;
}

//获得NT文件头
PIMAGE_NT_HEADERS getNTHeader(LPVOID pBuffer){
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pBuffer);
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pBuffer+pDosHeader->e_lfanew);
	return pNTHeader;
}


//获得PE文件头
PIMAGE_FILE_HEADER getPEHeader(LPVOID pBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	pNTHeader=getNTHeader(pBuffer);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	return pPEHeader;
}


//获得可选的PE头
PIMAGE_OPTIONAL_HEADER32 getOptionHeader(LPVOID pBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pPEHeader = getPEHeader(pBuffer);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	return pOptionHeader;
}

//获得节表头
PIMAGE_SECTION_HEADER getSectionHeader(LPVOID pBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	
	
	pPEHeader = getPEHeader(pBuffer);
	pOptionHeader = getOptionHeader(pBuffer);
	WORD sizeOfOptionHeader=pPEHeader->SizeOfOptionalHeader;
	pSectionHeader=(PIMAGE_SECTION_HEADER)((char*)pOptionHeader+sizeOfOptionHeader);
	return 	pSectionHeader;
}

//获取节表了
//index 第几个节表
PIMAGE_SECTION_HEADER getSection(LPVOID pBuffer,WORD index){
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	

	
	pSectionHeader=getSectionHeader(pBuffer);
	
	WORD sectionNum=getSectionNum(pBuffer);

	if(index<1 || index>sectionNum){
		printf("getSection Error,no section of this index:%d\n",index);
		return NULL;
	}

	pSectionHeader=(PIMAGE_SECTION_HEADER)((char*)pSectionHeader+40*(index-1));
	
	return pSectionHeader;

}	

//获得节的数量
WORD getSectionNum(LPVOID pBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader = getPEHeader(pBuffer);
	return pPEHeader->NumberOfSections;
}


