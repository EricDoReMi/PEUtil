#include "PEUtil.h"


//��ȡ�ļ���С
int getFileSize(FILE *P_file){
	int filesize=0;
	if(P_file){
		fseek(P_file,0,SEEK_END);
		filesize=ftell(P_file);
		fseek(P_file, 0, SEEK_SET);
	}else{
		printf("getFileSize Failed---�ļ�ָ��ΪNULL");
	}
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
		printf("ReadPEFile Failed---�޷���EXE �ļ�,%s!\n",lpszFile);
		return 0;
	}	
    //��ȡ�ļ���С		

    fileSize = getFileSize(pFile);		

	//���仺����	
	pFileBufferTmp = malloc(fileSize);	
		
	if(!pFileBufferTmp)	
	{	
		printf("ReadPEFile  Failed---��ȡPE�ļ������ռ�ʧ��%s!\n",lpszFile);
		fclose(pFile);
		pFile=NULL;
		pFileBufferTmp=NULL;
		return 0;
	}	

	memset(pFileBufferTmp,0,fileSize);

	//���ļ����ݶ�ȡ��������	
	size_t n = fread(pFileBufferTmp, 1, fileSize, pFile);	
	if(!n)	
	{	
		printf("ReadPEFile Failed---��ȡPE�ļ�����ʧ��,%s!\n",lpszFile);
		free(pFileBufferTmp);
		fclose(pFile);
		pFile=NULL;
		pFileBufferTmp=NULL;
		return 0;
	}	

	if(!checkIsPEFile(pFileBufferTmp)){
		printf("ReadPEFile Failed---���Ǳ�׼PE�ļ�,%s!\n",lpszFile);
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
	printf("ReadPEFile successed,%s!\n",lpszFile);
    return (DWORD)n;		
	
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
	if(!checkIsPEFile(pFileBuffer)){
		printf("CopyFileBufferToImageBuffer Failed---pFileBuffer���Ǳ�׼PE�ļ�!\n");
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
		printf("malloc PImageBufferʧ��! ");
		
		return 0;
	}
	
	memset(pImageBufferTmp,0,sizeOfImage);

	//============��pFileBuffer���ݶ�ȡ��pImageBuffer��=========

	//��ȡHeaders

	memcpy(pImageBufferTmp,pFileBuffer,POptionPEHeader->SizeOfHeaders);

	DWORD virtualAddress=0;
	DWORD sizeOfRawData=0;
	DWORD pointerToRawData=0;

	
	//���ݽڱ��е���Ϣѭ����FileBuffer�еĽڿ�����ImageBuffer��
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
//CopyImageBufferToNewBuffer:��ImageBuffer�е����ݸ��Ƶ��µĻ���������ImageBuffer��ԭΪ�ļ���PE��ʽ							
//����˵����							
//pImageBuffer ImageBufferָ��							
//pNewBuffer NewBufferָ��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С							
//**************************************************************************							
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer){
	if(!checkIsPEFile(pImageBuffer)){
		printf("CopyImageBufferToNewBuffer Failed---pImageBuffer���Ǳ�׼PE�ļ�!\n");
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
		printf("malloc pNewBufferTmpʧ��! ");
		
		return 0;
	}
	
	memset(pNewBufferTmp,0,sizeOfNewBuffer);
	
	//============��pImageBuffer���ݶ�ȡ��pNewBuffer��=========
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pImageBuffer);
	DWORD i=0;
	//��ȡHeaders
	for(i=0;i<sizeOfHeaders;i++)
	{
		*((char*)pNewBufferTmp+i)=*((char*)pImageBuffer+i);
	}

	DWORD virtualAddress=0;
	DWORD sizeOfRawData=0;
	DWORD pointerToRawData=0;


	//���ݽڱ��е���Ϣѭ����pImageBuffer�еĽڿ�����pNewBuffer��
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
//MemeryTOFile:���ڴ��е����ݸ��Ƶ��ļ�							
//����˵����							
//pMemBuffer �ڴ������ݵ�ָ��							
//size Ҫ���ƵĴ�С							
//lpszFile Ҫ�洢���ļ�·��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С							
//**************************************************************************							
DWORD MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile){
	if(!checkIsPEFile(pMemBuffer)){
		printf("CopyImageBufferToNewBuffer Failed---pMemBuffer���Ǳ�׼PE�ļ�,%s!\n",lpszFile);
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
int checkIsPEFile(LPVOID pBuffer){
		//�ж��Ƿ�����Ч��MZ��־	
	if(*((PWORD)pBuffer) != IMAGE_DOS_SIGNATURE)	
	{	
		printf("������Ч��MZ��־\n");
		freePBuffer(pBuffer);
		return 0; 
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pBuffer);
		//�ж��Ƿ�����Ч��PE��־	
	if(*((PDWORD)((DWORD)pBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)	
	{	
		printf("������Ч��PE��־\n");
		free(pBuffer);
		return 0;
	}

	return 1;
}

//��ȡDos�ļ�ͷ
PIMAGE_DOS_HEADER getDosHeader(LPVOID pBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	return pDosHeader;
}

//���NT�ļ�ͷ
PIMAGE_NT_HEADERS getNTHeader(LPVOID pBuffer){
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pBuffer);
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pBuffer+pDosHeader->e_lfanew);
	return pNTHeader;
}


//���PE�ļ�ͷ
PIMAGE_FILE_HEADER getPEHeader(LPVOID pBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	pNTHeader=getNTHeader(pBuffer);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	return pPEHeader;
}


//��ÿ�ѡ��PEͷ
PIMAGE_OPTIONAL_HEADER32 getOptionHeader(LPVOID pBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pPEHeader = getPEHeader(pBuffer);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	return pOptionHeader;
}

//��ýڱ�ͷ
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

//��ȡ�ڱ���
//index �ڼ����ڱ�
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

//��ýڵ�����
WORD getSectionNum(LPVOID pBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader = getPEHeader(pBuffer);
	return pPEHeader->NumberOfSections;
}


