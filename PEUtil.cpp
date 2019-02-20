#include "PEUtil.h"
LPVOID pFileBuffer=NULL;

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
int InitFileBuffer(LPSTR lpszFile)		
{		
	FILE *pFile = NULL;	
	DWORD fileSize = 0;	

		
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
	pFileBuffer = malloc(fileSize);	
		
	if(!pFileBuffer)	
	{	
		printf(" ��ȡPE�ļ������ռ�ʧ��! ");
		fclose(pFile);
		pFileBuffer=NULL;
		return 0;
	}	
	//���ļ����ݶ�ȡ��������	
	size_t n = fread(pFileBuffer, fileSize, 1, pFile);	
	if(!n)	
	{	
		printf(" ��ȡPE�ļ�����ʧ��! ");
		free(pFileBuffer);
		fclose(pFile);
		pFileBuffer=NULL;
		return 0;
	}	
	//�ر��ļ�	
	fclose(pFile);	
    return 1;		
	
}

//�ͷ�FillBuffer
void freePFileBuffer(){

	if(pFileBuffer){
		free(pFileBuffer);
		pFileBuffer=NULL;
	}
}

//����ǲ���PE�ļ�
//return 0 ʧ�� 1 �ɹ�
int checkIsPEFile(){
		//�ж��Ƿ�����Ч��MZ��־	
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)	
	{	
		printf("������Ч��MZ��־\n");
		free(pFileBuffer);
		return 0; 
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader();
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
PIMAGE_DOS_HEADER getDosHeader(){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	return pDosHeader;
}

//���NT�ļ�ͷ
PIMAGE_NT_HEADERS getNTHeader(){
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader();
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
	return pNTHeader;
}


//���PE�ļ�ͷ
PIMAGE_FILE_HEADER getPEHeader(){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	pNTHeader=getNTHeader();
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	return pPEHeader;
}


//��ÿ�ѡ��PEͷ
PIMAGE_OPTIONAL_HEADER32 getOptionHeader(){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pPEHeader = getPEHeader();
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	return pOptionHeader;
}

//��ýڱ�ͷ
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
