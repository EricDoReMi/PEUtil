#include "PEUtil.h"


//��ȡ�ļ���С
int getFileSize(FILE *P_file){
	int filesize=0;
	fseek(P_file,0,SEEK_END);
	filesize=ftell(P_file);
	fseek(P_file, 0, SEEK_SET);
	return filesize;
}

//��ȡ��FileBuffer
//return 0 ʧ�� 1 �ɹ�
//��������							
//**************************************************************************							
//ReadPEFile:���ļ���ȡ��������							
//����˵����							
//lpszFile �ļ�·��							
//pFileBuffer ������ָ��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻�ʵ�ʶ�ȡ�Ĵ�С							
//**************************************************************************							
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer)		
{		
	FILE *pFile = NULL;	
	DWORD fileSize = 0;	
	LPVOID pFileBufferTmp=NULL;
		
	//���ļ�	
    pFile = fopen(lpszFile, "rb");		
	if(!pFile)	
	{	
		printf(" �޷��� EXE �ļ�! ");
		return 0;
	}	
    //��ȡ�ļ���С		

    fileSize = getFileSize(pFile);		

	//���仺����	
	pFileBufferTmp = malloc(fileSize);	
		
	if(!pFileBufferTmp)	
	{	
		printf(" ��ȡPE�ļ������ռ�ʧ��! ");
		fclose(pFile);
		pFile=NULL;
		pFileBufferTmp=NULL;
		return 0;
	}	

	memset(pFileBufferTmp,0,fileSize);

	//���ļ����ݶ�ȡ��������	
	size_t n = fread(pFileBufferTmp, fileSize, 1, pFile);	
	if(!n)	
	{	
		printf(" ��ȡPE�ļ�����ʧ��! ");
		free(pFileBufferTmp);
		fclose(pFile);
		pFile=NULL;
		pFileBufferTmp=NULL;
		return 0;
	}	
	//�ر��ļ�	
	fclose(pFile);
	pFile=NULL;
	*pFileBuffer=pFileBufferTmp;
    return n;		
	
}

//**************************************************************************							
//CopyFileBufferToImageBuffer:���ļ���FileBuffer���Ƶ�ImageBuffer							
//����˵����							
//pFileBuffer  FileBufferָ��							
//pImageBuffer ImageBufferָ��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С							
//**************************************************************************
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer){
	return 0;
}							
//**************************************************************************							
//CopyImageBufferToNewBuffer:��ImageBuffer�е����ݸ��Ƶ��µĻ�����							
//����˵����							
//pImageBuffer ImageBufferָ��							
//pNewBuffer NewBufferָ��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С							
//**************************************************************************							
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer){
	return 0;
}							
//**************************************************************************							
//MemeryTOFile:���ڴ��е����ݸ��Ƶ��ļ�							
//����˵����							
//pMemBuffer �ڴ������ݵ�ָ��							
//size Ҫ���ƵĴ�С							
//lpszFile Ҫ�洢���ļ�·��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С							
//**************************************************************************							
BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile){
	return 0;
}							
//**************************************************************************							
//RvaToFileOffset:���ڴ�ƫ��ת��Ϊ�ļ�ƫ��							
//����˵����							
//pFileBuffer FileBufferָ��							
//dwRva RVA��ֵ							
//����ֵ˵����							
//����ת�����FOA��ֵ  ���ʧ�ܷ���0							
//**************************************************************************							
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva){
	return 0;
}

//�ͷ�Buffer
void freePBuffer(LPVOID pBuffer){
	
	if(pBuffer){
		free(pBuffer);
		pBuffer=NULL;
	}
}

//����ǲ���PE�ļ�
//return 0 ʧ�� 1 �ɹ�
int checkIsPEFile(LPVOID pFileBuffer){
		//�ж��Ƿ�����Ч��MZ��־	
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)	
	{	
		printf("������Ч��MZ��־\n");
		freePBuffer(pFileBuffer);
		return 0; 
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pFileBuffer);
		//�ж��Ƿ�����Ч��PE��־	
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)	
	{	
		printf("������Ч��PE��־\n");
		free(pFileBuffer);
		return 0;
	}

	return 1;
}

//��ȡDos�ļ�ͷ
PIMAGE_DOS_HEADER getDosHeader(LPVOID pFileBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	return pDosHeader;
}

//���NT�ļ�ͷ
PIMAGE_NT_HEADERS getNTHeader(LPVOID pFileBuffer){
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pFileBuffer);
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
	return pNTHeader;
}


//���PE�ļ�ͷ
PIMAGE_FILE_HEADER getPEHeader(LPVOID pFileBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	pNTHeader=getNTHeader(pFileBuffer);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	return pPEHeader;
}


//��ÿ�ѡ��PEͷ
PIMAGE_OPTIONAL_HEADER32 getOptionHeader(LPVOID pFileBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pPEHeader = getPEHeader(pFileBuffer);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	return pOptionHeader;
}

//��ýڱ�ͷ
PIMAGE_SECTION_HEADER getSectionHeader(LPVOID pFileBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	
	
	pPEHeader = getPEHeader(pFileBuffer);
	pOptionHeader = getOptionHeader(pFileBuffer);
	WORD sizeOfOptionHeader=pPEHeader->SizeOfOptionalHeader;
	pSectionHeader=(PIMAGE_SECTION_HEADER)((char*)pOptionHeader+sizeOfOptionHeader);
	return 	pSectionHeader;
}

//��ýڵ�����
WORD getSectionNum(LPVOID pFileBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader = getPEHeader(pFileBuffer);
	return pPEHeader->NumberOfSections;
}


