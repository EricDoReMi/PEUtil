#include "PEUtil.h"
LPVOID pFileBuffer=NULL;

//获取文件大小
int getFileSize(FILE *P_file){
	int filesize=0;
	fseek(P_file,0,SEEK_END);
	filesize=ftell(P_file);
	fseek(P_file, 0, SEEK_SET);
	return filesize;
}

//读取到FileBuffer
//return 0 失败 1 成功
int InitFileBuffer(LPSTR lpszFile)		
{		
	FILE *pFile = NULL;	
	DWORD fileSize = 0;	

		
	//打开文件	
    pFile = fopen(lpszFile, "rb");		
	if(!pFile)	
	{	
		printf(" 无法打开 EXE 文件! ");
		return 0;
	}	
    //读取文件大小		

    fileSize = getFileSize(pFile);		

	//分配缓冲区	
	pFileBuffer = malloc(fileSize);	
		
	if(!pFileBuffer)	
	{	
		printf(" 读取PE文件后分配空间失败! ");
		fclose(pFile);
		pFileBuffer=NULL;
		return 0;
	}	
	//将文件数据读取到缓冲区	
	size_t n = fread(pFileBuffer, fileSize, 1, pFile);	
	if(!n)	
	{	
		printf(" 读取PE文件数据失败! ");
		free(pFileBuffer);
		fclose(pFile);
		pFileBuffer=NULL;
		return 0;
	}	
	//关闭文件	
	fclose(pFile);	
    return 1;		
	
}

//释放FillBuffer
void freePFileBuffer(){

	if(pFileBuffer){
		free(pFileBuffer);
		pFileBuffer=NULL;
	}
}

//检查是不是PE文件
//return 0 失败 1 成功
int checkIsPEFile(){
		//判断是否是有效的MZ标志	
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)	
	{	
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return 0; 
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader();
		//判断是否是有效的PE标志	
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)	
	{	
		printf("不是有效的PE标志\n");
		free(pFileBuffer);
		return 0;
	}

	return 1;
}

//获取Dos文件头
PIMAGE_DOS_HEADER getDosHeader(){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	return pDosHeader;
}

//获得NT文件头
PIMAGE_NT_HEADERS getNTHeader(){
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader();
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
	return pNTHeader;
}


//获得PE文件头
PIMAGE_FILE_HEADER getPEHeader(){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	pNTHeader=getNTHeader();
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	return pPEHeader;
}


//获得可选的PE头
PIMAGE_OPTIONAL_HEADER32 getOptionHeader(){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pPEHeader = getPEHeader();
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	return pOptionHeader;
}

//获得节表头
PIMAGE_SECTION_HEADER getSectionHeader(){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	
	
	pPEHeader = getPEHeader();
	pOptionHeader = getOptionHeader();
	WORD sizeOfOptionHeader=pPEHeader->SizeOfOptionalHeader;
	pSectionHeader=(PIMAGE_SECTION_HEADER)(pOptionHeader+sizeOfOptionHeader);
	return 	pSectionHeader;
}
