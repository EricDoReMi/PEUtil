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
		return 0;
	}	

	memset(pFileBufferTmp,0,fileSize);

	//���ļ����ݶ�ȡ��������	
	DWORD n = (DWORD)fread(pFileBufferTmp, fileSize, 1, pFile);	
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

	if(!checkIsPEFile(pFileBuffer)){
		printf("CopyFileBufferToImageBuffer Failed---pFileBuffer���Ǳ�׼PE�ļ�!\n");
		return 0;
	}

	LPVOID pImageBufferTmp=NULL;
	PIMAGE_OPTIONAL_HEADER32 POptionPEHeader=getOptionHeader(pFileBuffer);
	DWORD sizeOfImage=POptionPEHeader->SizeOfImage;
	DWORD sizeOfHeaders=POptionPEHeader->SizeOfHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);
	WORD sectionNum=getSectionNum(pFileBuffer);
	
	pImageBufferTmp=malloc(sizeOfImage);
	if(!pImageBufferTmp){	

		printf("CopyFileBufferToImageBuffer---malloc PImageBufferʧ��!\n");

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
		
		pSectionHeader=pSectionHeader+1;

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
		return 0;
	}
	LPVOID pNewBufferTmp=NULL;
	PIMAGE_OPTIONAL_HEADER32 POptionPEHeader=getOptionHeader(pImageBuffer);
	DWORD sizeOfHeaders=POptionPEHeader->SizeOfHeaders;
	
	WORD sectionNum=getSectionNum(pImageBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader=getSection(pImageBuffer,sectionNum);

	DWORD pointerToRawDataLastSection=pLastSectionHeader->PointerToRawData;
	DWORD sizeOfRawDataLastSection=pLastSectionHeader->SizeOfRawData;
	DWORD sizeOfNewBuffer=pointerToRawDataLastSection+sizeOfRawDataLastSection;
	

	pNewBufferTmp=malloc(sizeOfNewBuffer);
	if(!pNewBufferTmp)	
	{	

		printf("CopyImageBufferToNewBuffer---malloc pNewBufferTmpʧ��!\n ");
		
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
		
		pSectionHeader=pSectionHeader+1;

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
		return 0;
	}
	FILE *p_file=NULL;
	p_file=fopen(lpszFile,"wb");
	if(p_file){
		DWORD writeSize=(DWORD)fwrite(pMemBuffer,1,size,p_file);
		
		fclose(p_file);
		p_file=NULL;
		

		if(!writeSize){

				printf("MemeryTOFile---Write File failed!\n");
				return 0;
		}
		
		return writeSize;
	}

		printf("MemeryTOFile---open File failed!\n");
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
	if(!checkIsPEFile(pFileBuffer)){
		printf("RvaToFileOffset Failed---pFileBuffer���Ǳ�׼PE�ļ�!\n");
		return 0;
	}

	
	WORD sectionNum=getSectionNum(pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 POptionPEHeader=getOptionHeader(pFileBuffer);
	DWORD imageBase = POptionPEHeader->ImageBase;
	DWORD tmpImageHigh=dwRva-imageBase;
	DWORD i=0;
	DWORD virtualAddress=0;
	DWORD indexSection=0;
	for(i=0;i<sectionNum;i++){
		
		virtualAddress=pSectionHeader->VirtualAddress;
		DWORD misc=pSectionHeader->Misc.VirtualSize;
		
		if(tmpImageHigh>=virtualAddress && tmpImageHigh<=(virtualAddress+misc)){
			indexSection=i+1;
			//�ҵ������ڽڵ�λ��
			return tmpImageHigh-virtualAddress+(pSectionHeader->PointerToRawData);
			
		}
		
		pSectionHeader=pSectionHeader+1;
	}

	
	return 0;
}

//**************************************************************************							
//FileOffsetToRva:���ڴ�ƫ��ת��Ϊ�ļ�ƫ��							
//����˵����							
//pFileBuffer FileBufferָ��							
//dwFileOffSet RVA��ֵ							
//����ֵ˵����							
//����ת�����RVA��ֵ  ���ʧ�ܷ���0							
//**************************************************************************							
DWORD FileOffsetToRva(IN LPVOID pFileBuffer,IN DWORD dwFileOffSet){
	if(!checkIsPEFile(pFileBuffer)){
		printf("RvaToFileOffset Failed---pFileBuffer���Ǳ�׼PE�ļ�!\n");

		return 0;
	}

	
	WORD sectionNum=getSectionNum(pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 POptionPEHeader=getOptionHeader(pFileBuffer);
	DWORD imageBase = POptionPEHeader->ImageBase;


	DWORD i=0;
	DWORD virtualAddress=0;
	DWORD indexSection=0;
	for(i=0;i<sectionNum;i++){
		
		virtualAddress=pSectionHeader->VirtualAddress;
		DWORD misc=pSectionHeader->Misc.VirtualSize;
		DWORD pointerToRawData=pSectionHeader->PointerToRawData;
		DWORD sizeOfRawData=pSectionHeader->SizeOfRawData;
		
		if(dwFileOffSet>=pointerToRawData && dwFileOffSet<=(pointerToRawData+sizeOfRawData)){
			indexSection=i+1;
			//�ҵ������ڽڵ�λ��
			return imageBase+virtualAddress+(dwFileOffSet-pointerToRawData);
			
		}
		
		pSectionHeader=pSectionHeader+1;
	}

	
	return 0;
}

//�ͷ�Buffer
void freePBuffer(LPVOID pBuffer){
	
		free(pBuffer);
		pBuffer=NULL;
	
}

//����ǲ���PE�ļ�
//return 0 ʧ�� 1 �ɹ�
int checkIsPEFile(LPVOID pBuffer){
		//�ж��Ƿ�����Ч��MZ��־	
	if(*((PWORD)pBuffer) != IMAGE_DOS_SIGNATURE)	
	{	
		printf("������Ч��MZ��־\n");
		
		return 0; 
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pBuffer);
		//�ж��Ƿ�����Ч��PE��־	
	if(*((PDWORD)((DWORD)pBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)	
	{	
		
		printf("������Ч��PE��־\n");
		
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
//����ֵ���ɹ����ظýڱ�ͷ��ʧ���򷵻�NULL
PIMAGE_SECTION_HEADER getSection(LPVOID pBuffer,WORD index){
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	

	
	pSectionHeader=getSectionHeader(pBuffer);
	
	WORD sectionNum=getSectionNum(pBuffer);

	if(index<1 || index>sectionNum){
		printf("getSection Error,no section of this index:%d\n",index);
		return NULL;
	}

	pSectionHeader=pSectionHeader+(index-1);
	
	return pSectionHeader;

}	

//��ýڵ�����
WORD getSectionNum(LPVOID pBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader = getPEHeader(pBuffer);
	return pPEHeader->NumberOfSections;
}



//��ShellCode��ӵ�ĳ��Section��
//pathName:Դ�ļ�·��
//pathNameDes:Ŀ���ļ�·��
//pshellCode:shellCode��ַ
//shellCodeLength:shellCode�ĳ���
//sectionNum:�ڵĵ�ַ��
//����ֵ:�ɹ�����1,ʧ�ܷ���0
DWORD addShellCodeIntoSection(char* pathName,char* pathNameDes,PBYTE pshellCode,DWORD shellCodeLength,WORD sectionNum){

	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;

	//FileToFileBuffer
	if(!ReadPEFile(pathName,&pFileBuffer)){
		return 0;
	}

	DWORD copySize=0;

	//FileBufferToImageBuffer
	copySize= CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
	
	if(!copySize){
		freePBuffer(pFileBuffer);
		printf("addShellCodeIntoSection---CopyFileBufferToImageBuffer Failed!\n");	
		return 0;
	}
	
	PIMAGE_SECTION_HEADER pSectionHeader=getSection(pFileBuffer,sectionNum);
	
	if(!pSectionHeader){
		freePBuffer(pFileBuffer);	
		freePBuffer(pImageBuffer);
		printf("addShellCodeIntoSection Failed!---SectionNum:%d ������\n",sectionNum);	
		return 0;
	}

	if(!checkSectionHeaderCouldWriteCode(pSectionHeader,shellCodeLength)){
		freePBuffer(pFileBuffer);	
		freePBuffer(pImageBuffer);
		printf("addShellCodeIntoSection Failed!---Section:%d û���㹻�Ŀռ���shellCode\n",sectionNum);
	}


	PBYTE pcodeBegin=NULL;
	pcodeBegin=getCodeBeginFromImageBuffer(pImageBuffer,pSectionHeader);
	

	//��shellCode���Ƶ�ImageBuffer��Ӧsection��
	memcpy(pcodeBegin,pshellCode,shellCodeLength);

	LPVOID pNewBuffer=NULL;
	
	
	copySize=CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	
	freePBuffer(pImageBuffer);

	if(!copySize){
		printf("CopyImageBufferToNewBuffer Failed!\n");
		return 0;
	}

	copySize=MemeryTOFile(pNewBuffer,copySize,pathNameDes);
	freePBuffer(pNewFileBuffer);

	if(!copySize){
		printf("MemeryTOFile Failed!\n");
		return 0;
	}

	return 1;
}


//�ж�Section�Ƿ��㹻�洢shellCode�Ĵ���
//pSectionHeader:Ҫ��������section��Header
//shellCodeLength:����������
//����ֵ:�ɹ��򷵻�1��ʧ���򷵻�0
DWORD checkSectionHeaderCouldWriteCode(IN PIMAGE_SECTION_HEADER pSectionHeader,DWORD shellCodeLength){
	if((pSectionHeader->SizeOfRawData<pSectionHeader->Misc.VirtualSize) || ((pSectionHeader->SizeOfRawData-pSectionHeader->Misc.VirtualSize)<shellCodeLength)){
		return 0;
	}
	return 1;
}



//��ImageBuffer�л���ܹ�ע������λ��
//����ע��Ĵ�����ImageBuffer�е�λ����
PBYTE getCodeBeginFromImageBuffer(IN LPVOID pImageBuffer,IN PIMAGE_SECTION_HEADER pSectionHeader){
	PBYTE pcodeBegin=NULL;
	pcodeBegin=(PBYTE)((DWORD)pImageBuffer+pSectionHeader->VirtualAddress+pSectionHeader->Misc.VirtualSize);
	return pcodeBegin;
}

//��ImageBuffer�еĵ�ַת��Ϊ����ʱ�ĵ�ַ
//pImageBuffer
//imageBufferRunAddr��ImageBuffer�еĵ�ַ��
//��������ʱ�ĵ�ַ
DWORD changeImageBufferAddressToRunTimeAddress(IN LPVOID pImageBuffer,DWORD imageBufferRunAddr){
	DWORD callAddressTo=0;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader = getOptionHeader(pImageBuffer);
	callAddressTo=((pOptionHeader->ImageBase)+(imageBufferRunAddr-(DWORD)pImageBuffer));
	
	return callAddressTo;
	
}

//��ImageBuffer�еĵ�ַת��ΪE8��E9ָ�������ת�ĵ�ַ��Ӳ����
//pImageBuffer
//imageBufferRunAddr��ImageBuffer�еĵ�ַ��
//E8E9RunTimeAddress:E8��E9ָ������ʱ�ĵ�ַ
DWORD changeE8E9AddressFromImageBuffer(IN LPVOID pImageBuffer,DWORD imageBufferRunAddr,DWORD E8E9RunTimeAddress){
	DWORD runTimeAddress=changeImageBufferAddressToRunTimeAddress(pImageBuffer,imageBufferRunAddr);
	DWORD returnAddressTo=changeE8E9AddressFromRunTimeBuffer(E8E9RunTimeAddress,runTimeAddress);
	return returnAddressTo;
	
}

//��RunTImeBuffer�еĵ�ַת��ΪE8��E9ָ�������ת�ĵ�ַ��Ӳ����
//E8E9RunTimeAddress:E8��E9ָ������ʱ�ĵ�ַ
//rumTimeAddress:Ҫת��������ʱ��ַ
//���أ�ת�����Ӳ�����ַ
DWORD changeE8E9AddressFromRunTimeBuffer(DWORD E8E9RunTimeAddress,DWORD rumTimeAddress){
	DWORD returnAddress=0;
	returnAddress=rumTimeAddress-(E8E9RunTimeAddress+5);
	return returnAddress;
	
}

//��ó�������ʱ��ڵĵ�ַ
//pBuffer
//������ڵ�ַ
PBYTE getEntryRunTimeAddress(LPVOID pBuffer){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader= getOptionHeader(pBuffer);

	return (PBYTE)(pOptionHeader->ImageBase+pOptionHeader->AddressOfEntryPoint);

}

//�޸ĳ�������ʱ��ڵ�ַ
//pImageBuffer
//imageBufferRunAddress��ImageBuffer�еĵ�ַ��
void changeEntryPosByImageBufferAddress(LPVOID pImageBuffer,DWORD imageBufferRunAddress){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader= getOptionHeader(pImageBuffer);
	pOptionHeader->AddressOfEntryPoint=imageBufferRunAddress-(DWORD)pImageBuffer;
}

//�޸�section��Ȩ��
//pBuffer
//sectionNum Section�ĵ�ַ
//characteristics�������Ȩ�ޣ���0x60000020
//�ɹ�������1��ʧ�ܣ�����0
DWORD changeSectionCharacteristics(LPVOID pBuffer,WORD sectionNum,DWORD characteristics){
	PIMAGE_SECTION_HEADER pSectionHeader=getSection(pBuffer,sectionNum);
	if(pSectionHeader){
		pSectionHeader->Characteristics=characteristics;
		return 1;
	}else{
		printf("changeSectionCharacteristics Failed!\n");
		return 0;
	}

}

//��pBuffer�н�PE��NTͷ������Dosͷ��
//pBuffer
//����ֵ:Dosͷ�µļ�϶�Ĵ�С��0:Dosͷ��û�м�϶
DWORD topPENTHeader(IN LPVOID pBuffer){
	DWORD copySize=0;
	PIMAGE_DOS_HEADER dosHeader = getDosHeader(pBuffer);
	PIMAGE_NT_HEADERS ntHeader = getNTHeader(pBuffer);
	PIMAGE_FILE_HEADER fileHeader = getPEHeader(pBuffer);
	WORD sectionNum=getSectionNum(pBuffer);
	//Dos�������ֶεĿ�ͷ
	DWORD endDosPointNext=(DWORD)pBuffer+sizeof(IMAGE_DOS_HEADER);


	copySize=0;

	if((DWORD)ntHeader>endDosPointNext || (DWORD)ntHeader==endDosPointNext){
		copySize=(DWORD)ntHeader-endDosPointNext;
	}else{
		printf("topPENTHeader failed---ntHeader<endDosPointNext");

	}

	if(!copySize && sectionNum<1){
		return copySize;
	}
	
	//��õ�һ���ڱ�ͷ
	PIMAGE_SECTION_HEADER pSectionHeader1 = getSection(pBuffer,1);

	//����NTͷ������ԭNTͷʣ��Ĳ�����0
	*((PIMAGE_NT_HEADERS)endDosPointNext)=*ntHeader;
	
	PIMAGE_SECTION_HEADER newPSectionHeader1=(PIMAGE_SECTION_HEADER)((PIMAGE_NT_HEADERS)endDosPointNext+1);
	int i=0;

	for(i=0;i<sectionNum;i++){
		*(newPSectionHeader1+i)=*(pSectionHeader1+i);
	}


	char* fillZeroStart=(char*)(newPSectionHeader1+sectionNum);

	for(i=0;i<copySize;i++){
		*(fillZeroStart+i)=0;
	}
	
	dosHeader->e_lfanew=(endDosPointNext-(DWORD)pBuffer);

	return copySize;
}