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
    return fileSize;		
	
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
	
	DWORD i=0;
	DWORD virtualAddress=0;
	DWORD indexSection=0;
	for(i=0;i<sectionNum;i++){
		
		virtualAddress=pSectionHeader->VirtualAddress;
		DWORD misc=pSectionHeader->Misc.VirtualSize;
		
		if(dwRva>=virtualAddress && dwRva<(virtualAddress+misc)){
			indexSection=i+1;
			//�ҵ������ڽڵ�λ��
			return dwRva-virtualAddress+(pSectionHeader->PointerToRawData);
			
		}
		
		pSectionHeader=pSectionHeader+1;
	}

	
	return 0;
}

//**************************************************************************							
//RvaToSectionIndex:ͨ���ڴ�ƫ��Ѱ��sectionIndex							
//����˵����							
//pFileBuffer FileBufferָ��							
//dwRva RVA��ֵ							
//����ֵ˵����							
//�����ҵ���SectionNum�� ���ʧ�ܷ���0							
//**************************************************************************							
DWORD RvaToSectionIndex(IN LPVOID pFileBuffer,IN DWORD dwRva){
	if(!checkIsPEFile(pFileBuffer)){
		printf("RvaToFileOffset Failed---pFileBuffer���Ǳ�׼PE�ļ�!\n");
		return 0;
	}

	
	WORD sectionNum=getSectionNum(pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 POptionPEHeader=getOptionHeader(pFileBuffer);
	
	DWORD i=0;
	DWORD virtualAddress=0;
	DWORD indexSection=0;
	for(i=0;i<sectionNum;i++){
		
		virtualAddress=pSectionHeader->VirtualAddress;
		DWORD misc=pSectionHeader->Misc.VirtualSize;
		
		if(dwRva>=virtualAddress && dwRva<(virtualAddress+misc)){
			indexSection=i+1;
			//�ҵ������ڽڵ�λ��
			return indexSection;
			
		}
		
		pSectionHeader=pSectionHeader+1;
	}

	
	return 0;
}

//**************************************************************************							
//FileOffsetToRva:���ļ�ƫ��ת��Ϊ�ڴ�ƫ��							
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
		
		if(dwFileOffSet>=pointerToRawData && dwFileOffSet<(pointerToRawData+sizeOfRawData)){
			indexSection=i+1;
			//�ҵ������ڽڵ�λ��
			return virtualAddress+(dwFileOffSet-pointerToRawData);
			
		}
		
		pSectionHeader=pSectionHeader+1;
	}

	
	return 0;
}

//**************************************************************************							
//RvaToFileBufferAddress:���ڴ�ƫ��ת��ΪFileBuffer�еĵ�ַ��							
//����˵����							
//pFileBuffer FileBufferָ��							
//dwRva RVA��ֵ							
//����ֵ˵����							
//����ת�����FileAddress��ֵ  ���ʧ�ܷ���0							
//**************************************************************************							
DWORD RvaToFileBufferAddress(IN LPVOID pFileBuffer,IN DWORD dwRva){
	if(!checkIsPEFile(pFileBuffer)){
		printf("RvaToFileOffset Failed---pFileBuffer���Ǳ�׼PE�ļ�!\n");
		return 0;
	}

	
	WORD sectionNum=getSectionNum(pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);


	
	DWORD i=0;
	DWORD virtualAddress=0;
	DWORD indexSection=0;
	for(i=0;i<sectionNum;i++){
		
		virtualAddress=pSectionHeader->VirtualAddress;
		DWORD misc=pSectionHeader->Misc.VirtualSize;
		
		if(dwRva>=virtualAddress && dwRva<(virtualAddress+misc)){
			indexSection=i+1;
			//�ҵ������ڽڵ�λ��
			return ((DWORD)pFileBuffer+(dwRva-virtualAddress+(pSectionHeader->PointerToRawData)));
			
		}
		
		pSectionHeader=pSectionHeader+1;
	}

	
	return 0;
}

//**************************************************************************							
//FileBufferAddressToRva:��FileBuffer�еĵ�ַת��Ϊ�ڴ�ƫ��							
//����˵����							
//pFileBuffer FileBufferָ��							
//dwFileAddress fileBuffer�е�ַ						
//����ֵ˵����							
//����ת�����RVA��ֵ  ���ʧ�ܷ���0							
//**************************************************************************							
DWORD FileBufferAddressToRva(IN LPVOID pFileBuffer,IN DWORD dwFileAddress){
	if(!checkIsPEFile(pFileBuffer)){
		printf("RvaToFileOffset Failed---pFileBuffer���Ǳ�׼PE�ļ�!\n");

		return 0;
	}

	
	WORD sectionNum=getSectionNum(pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);
	
	DWORD gapImageBase=dwFileAddress-(DWORD)pFileBuffer;

	DWORD i=0;
	DWORD virtualAddress=0;
	DWORD indexSection=0;
	for(i=0;i<sectionNum;i++){
		
		virtualAddress=pSectionHeader->VirtualAddress;
		DWORD misc=pSectionHeader->Misc.VirtualSize;
		DWORD pointerToRawData=pSectionHeader->PointerToRawData;
		DWORD sizeOfRawData=pSectionHeader->SizeOfRawData;
		
		if(gapImageBase>=pointerToRawData && gapImageBase<=(pointerToRawData+sizeOfRawData)){
			indexSection=i+1;
			//�ҵ������ڽڵ�λ��
			return virtualAddress+(gapImageBase-pointerToRawData);
			
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

//��pBuffer�н�PE��NTͷ��Section��ͷ������Dosͷ��
//pBuffer
//����ֵ:Dosͷ�µļ�϶�Ĵ�С��0:Dosͷ��û�м�϶
DWORD topPENTAndSectionHeader(IN LPVOID pBuffer){
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
	DWORD i=0;

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

//��ýڱ�����һ���ֽڵ���һ���ֽڵĵ�ַ
//pBuffer
//����ֵ:LPVOID,����һ���ڱ�ָ�룬���������ڱ�
LPVOID getSectionEnderNext(IN LPVOID pBuffer){

	WORD sectionNum=getSectionNum(pBuffer);
	//��õ�һ���ڱ�ͷ
	PIMAGE_SECTION_HEADER pSectionHeader1 = getSection(pBuffer,1);

	LPVOID pSectionEnderNext=(LPVOID)(pSectionHeader1+sectionNum);

	return pSectionEnderNext;



}

//�ж��Ƿ�������һ���ڱ�,�����һ���ڱ���80���ֽ�ȫΪ0,��������
//pBuffer
//����ֵ:1�ɹ�,0ʧ��
DWORD checkCanAddSection(IN LPVOID pBuffer){


	char* fillZeroStart=(char*)getSectionEnderNext(pBuffer);

	int i=0;
	int checkLen=2*sizeof(IMAGE_SECTION_HEADER);
	for(i=0;i<checkLen;i++){
		if(*(fillZeroStart+i))return 0;
	}

	return 1;

}

//����һ����
//pImageBuffer
//sizeOfNewSection,�������ֽ���
//pNewBuffer���سɹ���newBuffer��ַ
//characteristics�������Ȩ�ޣ���0x60000020
//����ֵ 1�ɹ� 0ʧ��
DWORD addNewSection(IN LPVOID pImageBuffer,DWORD sizeOfNewSection,DWORD characteristics,OUT LPVOID* pNewImageBuffer){
	//���optionHeader������Ҫ������
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pImageBuffer);
	DWORD sizeOfImage=pOptionHeader->SizeOfImage;
	DWORD sectionAlignment=pOptionHeader->SectionAlignment;

	//�޸�sizeOfNewSection
	sizeOfNewSection=changeNumberByBase(sectionAlignment,sizeOfNewSection);

	DWORD newBufferSize=sizeOfImage+sizeOfNewSection;

	//�����ڴ����ڴ洢�µ�pBuffer
	LPVOID pNewImageBufferTmp=NULL;
	pNewImageBufferTmp=malloc(newBufferSize);

	if(!pNewImageBufferTmp)	
	{	

		printf("addNewSection Failed---malloc pNewImageBufferTmpʧ��!\n ");
		
		return 0;
	}
	
	memset(pNewImageBufferTmp,0,newBufferSize);
	
	//��pBuffer�����ݶ��뵽pNewBufferTmp
	memcpy(pNewImageBufferTmp,pImageBuffer,sizeOfImage);
	


	
	PIMAGE_FILE_HEADER fileHeader = getPEHeader(pNewImageBufferTmp);

	//ԭ��section������
	WORD sectionNumBefore=fileHeader->NumberOfSections;
	

	//�޸�sizeOfImage
	pOptionHeader=getOptionHeader(pNewImageBufferTmp);
	pOptionHeader->SizeOfImage=newBufferSize;
	

	//��������ڱ�ͷ
	PIMAGE_SECTION_HEADER pNewSectionHeader=(PIMAGE_SECTION_HEADER)getSectionEnderNext(pNewImageBufferTmp);
	
	//Copy���һ���ڱ�
	PIMAGE_SECTION_HEADER pLastSectionHeader=getSection(pNewImageBufferTmp,sectionNumBefore);
	*pNewSectionHeader=*(pLastSectionHeader);
	
	(fileHeader->NumberOfSections)++;

	//�޸������ڱ�����
	BYTE names[8]={'.','A','D','D',0};
	BYTE* pName=pNewSectionHeader->Name;
	memcpy(pName,names,8);
	
	//�޸������ڱ�����
	pNewSectionHeader->PointerToRawData=pLastSectionHeader->PointerToRawData+pLastSectionHeader->SizeOfRawData;
	pNewSectionHeader->SizeOfRawData=sizeOfNewSection;
	pNewSectionHeader->VirtualAddress=sizeOfImage;
	pNewSectionHeader->Characteristics=characteristics;
	pNewSectionHeader->Misc.VirtualSize=sizeOfNewSection-sectionAlignment+1;

	*pNewImageBuffer=pNewImageBufferTmp;
	

	
	return 1;
}


//���FileBuffer�Ĵ�С
DWORD getFileBufferSize(IN LPVOID pFileBuffer){
	DWORD sizeOfFileBuffer=0;
	PIMAGE_FILE_HEADER fileHeader = getPEHeader(pFileBuffer);
	WORD sectionNumBefore=fileHeader->NumberOfSections;
	
	PIMAGE_SECTION_HEADER pLastSectionHeader=(PIMAGE_SECTION_HEADER)getSection(pFileBuffer,sectionNumBefore);


	DWORD pointerToRawDataLastSection=pLastSectionHeader->PointerToRawData;
	DWORD sizeOfRawDataLastSection=pLastSectionHeader->SizeOfRawData;
	sizeOfFileBuffer=pointerToRawDataLastSection+sizeOfRawDataLastSection;

	return sizeOfFileBuffer;

}

//ֱ����FileBuffer������һ����
//pFileBuffer
//sizeOfNewSection,�������ֽ���
//pNewFileBuffer���سɹ���newFileBuffer��ַ
//characteristics�������Ȩ�ޣ���0x60000020
//����ֵ �����������׵�ַ��RVA 0ʧ��
DWORD addNewSectionByFileBuffer(IN LPVOID pFileBuffer,DWORD sizeOfNewSection,DWORD characteristics,OUT LPVOID* pNewFileBuffer){
	//���optionHeader������Ҫ������
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);

	DWORD sizeOfHeaders=pOptionHeader->SizeOfHeaders;
	DWORD sizeOfImage=pOptionHeader->SizeOfImage;
	DWORD sectionAlignment=pOptionHeader->SectionAlignment;
	DWORD fileAlignment=pOptionHeader->FileAlignment;

	
	DWORD sizeOfFileBuffer=getFileBufferSize(pFileBuffer);

	//�����ڼ���FileBuffer�е�������С
	DWORD newSizeOfFileSection=changeNumberByBase(fileAlignment,sizeOfNewSection);

	//�����ڼ���ImageBuffer�е�������С
	DWORD newSizeOfSectionImage=changeNumberByBase(sectionAlignment,sizeOfNewSection);

	//�µ�sizeOfImage
	DWORD newSizeOfImage=sizeOfImage+newSizeOfSectionImage;
	


	//�µ�FileBuffer�Ĵ�С
	DWORD newSizeOfBuffer=sizeOfFileBuffer+newSizeOfFileSection;

	

	//�����ڴ����ڴ洢�µ�pBuffer
	LPVOID pNewFileBufferTmp=NULL;
	pNewFileBufferTmp=malloc(newSizeOfBuffer);

	if(!pNewFileBufferTmp)	
	{	

		printf("addNewSectionByFileBuffer Failed---malloc pNewFileBufferTmpʧ��!\n ");
		
		return 0;
	}
	
	memset(pNewFileBufferTmp,0,newSizeOfBuffer);
	
	//��pBuffer�����ݶ��뵽pNewBufferTmp
	memcpy(pNewFileBufferTmp,pFileBuffer,sizeOfFileBuffer);
	
	PIMAGE_FILE_HEADER fileHeader = getPEHeader(pNewFileBufferTmp);
	
	WORD sectionNumBefore=fileHeader->NumberOfSections;

	//�޸�sizeOfImage
	pOptionHeader=getOptionHeader(pNewFileBufferTmp);
	pOptionHeader->SizeOfImage=newSizeOfImage;
	
	

	//��������ڱ�ͷ
	PIMAGE_SECTION_HEADER pNewSectionHeader=(PIMAGE_SECTION_HEADER)getSectionEnderNext(pNewFileBufferTmp);
	
	//Copy���һ���ڱ�
	PIMAGE_SECTION_HEADER pLastSectionHeader=getSection(pNewFileBufferTmp,sectionNumBefore);
	*pNewSectionHeader=*(pLastSectionHeader);
	
	
	(fileHeader->NumberOfSections)++;

	//�޸������ڱ�����
	BYTE names[8]={'.','A','D','D',0};
	BYTE* pName=pNewSectionHeader->Name;
	memcpy(pName,names,8);
	
	//�޸������ڱ�����
	pNewSectionHeader->PointerToRawData=pLastSectionHeader->PointerToRawData+pLastSectionHeader->SizeOfRawData;
	pNewSectionHeader->SizeOfRawData=newSizeOfFileSection;
	pNewSectionHeader->VirtualAddress=sizeOfImage;
	pNewSectionHeader->Characteristics=characteristics;
	pNewSectionHeader->Misc.VirtualSize=newSizeOfSectionImage-sectionAlignment+1;

	*pNewFileBuffer=pNewFileBufferTmp;
	

	
	return pNewSectionHeader->PointerToRawData;
}


//��չ���һ���ڱ�
//pBuffer
//addSize,���ӵ��ֽ���
//pNewBuffer���سɹ���newBuffer��ַ
//characteristics�������Ȩ�ޣ���0x60000020
//����ֵ 1�ɹ� 0ʧ��
DWORD extendTheLastSection(IN LPVOID pImageBuffer,DWORD addSizeNew,DWORD characteristics,OUT LPVOID* pNewImageBuffer){
	//���optionHeader������Ҫ������
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pImageBuffer);
	DWORD sizeOfImage=pOptionHeader->SizeOfImage;
	DWORD sectionAlignment=pOptionHeader->SectionAlignment;

	//���FileHeader������Ҫ������
	PIMAGE_FILE_HEADER fileHeader = getPEHeader(pImageBuffer);
	WORD sectionNum=fileHeader->NumberOfSections;

	
	
	//�޸�addSize
	DWORD sizeOfNewSection=changeNumberByBase(sectionAlignment,addSizeNew);


	DWORD newBufferSize=sizeOfImage+sizeOfNewSection;

	//�����ڴ����ڴ洢�µ�pBuffer
	LPVOID pNewImageBufferTmp=NULL;
	pNewImageBufferTmp=malloc(newBufferSize);

	if(!pNewImageBufferTmp)	
	{	

		printf("extendTheLastSection---malloc pNewImageBufferTmpʧ��!\n ");
		
		return 0;
	}
	
	memset(pNewImageBufferTmp,0,newBufferSize);
	
	

	//��pBuffer�����ݶ��뵽pNewBufferTmp
	memcpy(pNewImageBufferTmp,pImageBuffer,sizeOfImage);

	//�޸�pNewImageBufferTmp��SizeOfImage
	pOptionHeader=getOptionHeader(pNewImageBufferTmp);
	pOptionHeader->SizeOfImage=newBufferSize;
	
	//���pNewImageBufferTmp���һ���ڱ�
	PIMAGE_SECTION_HEADER pLastSectionHeader=getSection(pNewImageBufferTmp,sectionNum);
	

	//�޸�sizeOfImage
	pOptionHeader=getOptionHeader(pNewImageBufferTmp);
	pOptionHeader->SizeOfImage=newBufferSize;
	
	
	//�޸����һ���ڱ�����
	BYTE names[8]={'.','E','X','T','E','N','D',0};
	BYTE* pName=pLastSectionHeader->Name;
	memcpy(pName,names,8);
	
	//�޸����һ���ڱ�����
	pLastSectionHeader->SizeOfRawData+=sizeOfNewSection;
	pLastSectionHeader->Characteristics=characteristics;
	

	pLastSectionHeader->Misc.VirtualSize=pLastSectionHeader->SizeOfRawData-sectionAlignment+1;
	*pNewImageBuffer=pNewImageBufferTmp;
	

	
	return 1;
}

//�ϲ����н�
//pBuffer
//characteristics �ϲ���ֻ��һ���ڣ�Ҫ���У�������Ȩ��Ϊ0xE0000020������Ҫ���������ڣ�����������Ȩ�ޣ����޷�����
//pNewBuffer���سɹ���newBuffer��ַ
//����ֵ 1�ɹ� 0ʧ��
DWORD mergeAllSections(IN LPVOID pImageBuffer,DWORD characteristics,OUT LPVOID* pNewImageBuffer){
	//���optionHeader������Ҫ������
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pImageBuffer);
	DWORD sizeOfImage=pOptionHeader->SizeOfImage;
	DWORD sizeOfHeaders=pOptionHeader->SizeOfHeaders;
	DWORD sectionAlignment=pOptionHeader->SectionAlignment;

	//���FileHeader������Ҫ������
	PIMAGE_FILE_HEADER fileHeader = getPEHeader(pImageBuffer);
	WORD sectionNum=fileHeader->NumberOfSections;
	
	//������һ���ڱ�
	PIMAGE_SECTION_HEADER pLastSectionHeader=getSection(pImageBuffer,sectionNum);

	DWORD maxOfSize=0;
	if((pLastSectionHeader->SizeOfRawData) > (pLastSectionHeader->Misc.VirtualSize)){
		maxOfSize=pLastSectionHeader->SizeOfRawData;
	}else{
		maxOfSize=pLastSectionHeader->Misc.VirtualSize;
	}
	maxOfSize=changeNumberByBase(sectionAlignment,pLastSectionHeader->VirtualAddress+maxOfSize-sizeOfHeaders);
	

	//�����ڴ����ڴ洢�µ�pBuffer
	LPVOID pNewImageBufferTmp=NULL;
	pNewImageBufferTmp=malloc(maxOfSize+sizeOfHeaders);

	if(!pNewImageBufferTmp)	
	{	

		printf("extendTheLastSection---malloc pNewImageBufferTmpʧ��!\n ");
		
		return 0;
	}
	
	memset(pNewImageBufferTmp,0,maxOfSize+sizeOfHeaders);
	
	//��pBuffer�����ݶ��뵽pNewBufferTmp
	memcpy(pNewImageBufferTmp,pImageBuffer,sizeOfImage);

	//��õ�һ���ڱ�
	PIMAGE_SECTION_HEADER pFirstSectionHeader=getSection(pNewImageBufferTmp,1);

	

	
	//�޸ĵ�һ���ڱ�����
	BYTE names[8]={'.','M','E','R','G','E',0};
	BYTE* pName=pFirstSectionHeader->Name;
	memcpy(pName,names,8);
	

	

	//�޸ĵ�һ���ڱ�����
	pFirstSectionHeader->SizeOfRawData=maxOfSize;
	
	pFirstSectionHeader->Characteristics=characteristics;


	pFirstSectionHeader->Misc.VirtualSize=maxOfSize;


	//����һ���ڱ����0x28���ֽ�����
	if(sectionNum>1){
		memset(pFirstSectionHeader+1,0,sizeof(IMAGE_SECTION_HEADER));
	
	}
	
	//�޸�sizeOfImage��С
	pOptionHeader=getOptionHeader(pNewImageBufferTmp);
	pOptionHeader->SizeOfImage=maxOfSize+sizeOfHeaders;

	//��section�����޸�Ϊ1
	fileHeader = getPEHeader(pNewImageBufferTmp);
	fileHeader->NumberOfSections=1;

	*pNewImageBuffer=pNewImageBufferTmp;
	

	
	return 1;
}




//��changeNumber��ΪbaseNumber��������
//baseNum:����
//changeNumber:��Ҫ���õ���
//����ֵ:�ı���ֵ
DWORD changeNumberByBase(DWORD baseNumber,DWORD changeNumber){
	if(baseNumber<changeNumber){
		DWORD mul=changeNumber/baseNumber;

		return baseNumber*(mul+1);
	}else{
		return baseNumber;
	}


}


//===================PIMAGE_DATA_DIRECTORY=======================


//��index��ȡDataDirectoryTable��Ϣ
//pFileBuffer
//index ���,��Ŵ�1��ʼ,�� 1 ������
//���� PIMAGE_DATA_DIRECTORY
PIMAGE_DATA_DIRECTORY getDataDirectory(LPVOID pFileBuffer,DWORD index){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	PIMAGE_DATA_DIRECTORY pImageDataDirectory=pOptionHeader->DataDirectory;

	return  pImageDataDirectory+index-1;
	
}

//********************������********************************
//ͨ��������������ú�����ַRVA
//pFileBuffer
//pFunName �������ַ���ָ��
//����ֵ:�ɹ� �ú���RVA
DWORD GetFunctionRVAByName(LPVOID pFileBuffer,char* pFunName)
{
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	DWORD imageBase = pOptionHeader->ImageBase;
	

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,1);
	//��õ�������FileBuffer�е�Addressλ��
	DWORD exportDirectoryFileAddress =(DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pDataDirectory->VirtualAddress);

	//�ҵ�������
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=(PIMAGE_EXPORT_DIRECTORY)exportDirectoryFileAddress;
	
	DWORD i=0;
	DWORD j=0;

	PDWORD pFileAddressOfFunctions=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfFunctions));
	PDWORD pFileAddressOfNames=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNames));
	PWORD pFileAddressOfNameOrdinals=(PWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNameOrdinals));
	
	//��ӡ������Ϣ
	for(i=0;i<pExportDirectory->NumberOfNames;i++)
	{
		char* addressOfName=(char*)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,*(pFileAddressOfNames+i)));
		
		//�ҵ�������
		if(!strcmp(addressOfName,pFunName))
		{
			return (DWORD)(*(pFileAddressOfFunctions+(DWORD)(*(pFileAddressOfNameOrdinals+i))));
			
		}
	}

	printf("GetFunctionAddrByName failed---û�ж�Ӧ����:%s\n",pFunName);
	return NULL;
}

//ͨ������������Ż�ú�����ַRVA,���������.def�ļ��еĶ���
//pFileBuffer
//index ���
//����ֵ:�ɹ� �ú���RVA
DWORD GetFunctionRVAByOrdinals(LPVOID pFileBuffer,DWORD index)
{
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	DWORD imageBase = pOptionHeader->ImageBase;
	

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,1);
	//��õ�������FileBuffer�е�Addressλ��
	DWORD exportDirectoryFileAddress =(DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pDataDirectory->VirtualAddress);

	//�ҵ�������
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=(PIMAGE_EXPORT_DIRECTORY)exportDirectoryFileAddress;
	

	PDWORD pFileAddressOfFunctions=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfFunctions));


	index=index-(pExportDirectory->Base);

	if(index<0 || index>pExportDirectory->NumberOfFunctions)
	{
		printf("GetFunctionAddrByOrdinals failed---û�ж�Ӧ���:%d\n",index);
		return NULL;
	}

	return (DWORD)(*(pFileAddressOfFunctions+index));
		
}


//��ȡ������Ĵ�С,�����������еĺ�����ַ���������Ʊ�ͺ�����ű�Ĵ�С���Լ��������Ʊ���ָ����ַ����Ĵ�С
//pFileBuffer
//����ֵ �������С
DWORD getExportDirectorySize(LPVOID pFileBuffer){
	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,1);
	//��õ�������FileBuffer�е�Addressλ��
	DWORD exportDirectoryFileAddress =RvaToFileBufferAddress(pFileBuffer,pDataDirectory->VirtualAddress);
	//�ҵ�������
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=(PIMAGE_EXPORT_DIRECTORY)exportDirectoryFileAddress;

	DWORD totalSize=0;

	//IMAGE_EXPORT_DIRECTORY�Ĵ�С
	DWORD sizeOfExportDirectory=sizeof(IMAGE_EXPORT_DIRECTORY);

	//AddressOfFunctions���С
	DWORD sizeOfAddressOfFunctions=(pExportDirectory->NumberOfFunctions)*4;

	//AddressOfNameOrdinals���С
	DWORD sizeOfAddressOfNameOrdinals=(pExportDirectory->NumberOfNames)*2;

	//AddressOfNames���С
	DWORD sizeOfAddressOfNames=(pExportDirectory->NumberOfNames)*4;

	//�������Ʊ����к������ƴ�С���ܺ�
	DWORD sizeOfAddressStr=0;

	PDWORD pFileAddressOfNames=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNames));

	//ѭ��������������ַ��������С�����������β0
	DWORD i=0;

	for(i=0;i<pExportDirectory->NumberOfNames;i++){
		sizeOfAddressStr+=(strlen((char*)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,*(pFileAddressOfNames+i))))+1);
		
	}
	
	totalSize=sizeOfExportDirectory+sizeOfAddressOfFunctions+sizeOfAddressOfNameOrdinals+sizeOfAddressOfNames+sizeOfAddressStr;

	return totalSize;

}


//�ƶ�������
//pFileBuffer
//fileRVA �������ƶ�����RVA
void removeExportDirectory(LPVOID pFileBuffer,DWORD fileRVA){
	//�µĵ�������FileBuffer�е��׵�ַ
	DWORD newExportDirectoryFileBufferAddress=(DWORD)pFileBuffer+fileRVA;

	//���ڸ��Ʊ��ʱ��ָ��
	char* newExportDirectoryPointer=(char*)newExportDirectoryFileBufferAddress;

	//Ѱ�ҵ�����
	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,1);
	//��õ�������FileBuffer�е�Addressλ��
	DWORD exportDirectoryFileAddress =RvaToFileBufferAddress(pFileBuffer,pDataDirectory->VirtualAddress);
	//�ҵ�������
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=(PIMAGE_EXPORT_DIRECTORY)exportDirectoryFileAddress;

	//����AddressOfFunctions
	PDWORD pFileAddressOfFunctions=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfFunctions));

	memcpy(newExportDirectoryPointer,pFileAddressOfFunctions,(pExportDirectory->NumberOfFunctions)*4);
	
	//��¼newAddressOfFunctions
	PDWORD newAddressOfFunctions=(PDWORD)newExportDirectoryPointer;

	newExportDirectoryPointer+=(pExportDirectory->NumberOfFunctions)*4;
	
	//����AddressOfNames
	PDWORD pFileAddressOfNames=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNames));

	memcpy(newExportDirectoryPointer,pFileAddressOfFunctions,(pExportDirectory->NumberOfNames)*4);

    //��¼newFileAddressOfNames
	PDWORD newFileAddressOfNames=(PDWORD)newExportDirectoryPointer;

	newExportDirectoryPointer+=(pExportDirectory->NumberOfNames)*4;

	//����AddressOfNameOrdinals
	PWORD pFileAddressOfNameOrdinals=(PWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNameOrdinals));
	
	memcpy(newExportDirectoryPointer,pFileAddressOfNameOrdinals,(pExportDirectory->NumberOfNames)*2);

	//��¼newFileAddressOfNameOrdinals
	PDWORD newFileAddressOfNameOrdinals=(PDWORD)newExportDirectoryPointer;

	newExportDirectoryPointer+=(pExportDirectory->NumberOfNames)*2;

	//�������еĺ�����
	DWORD i=0;
	for(i=0;i<pExportDirectory->NumberOfNames;i++)
	{
		char* pCopyStrAddr=(char*)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,*(pFileAddressOfNames+i)));
		DWORD copySize=strlen(pCopyStrAddr)+1;
		memcpy(newExportDirectoryPointer,pCopyStrAddr,copySize);
		//printf("%s\n",newExportDirectoryPointer);
		
		*(newFileAddressOfNames+i)=(DWORD)FileBufferAddressToRva(pFileBuffer,(DWORD)newExportDirectoryPointer);
		newExportDirectoryPointer+=copySize;
				
	}

	//����IMAGE_EXPORT_DIRECTORY�ṹ

	//��¼newExportDirectoryAddr
	PIMAGE_EXPORT_DIRECTORY newExportDirectoryAddr=(PIMAGE_EXPORT_DIRECTORY)newExportDirectoryPointer;

	*(newExportDirectoryAddr)=*(pExportDirectory);

	//�޸�newExportDirectory�еĵ�ַ��
	newExportDirectoryAddr->AddressOfFunctions=(DWORD)FileBufferAddressToRva(pFileBuffer,(DWORD)newAddressOfFunctions);
	newExportDirectoryAddr->AddressOfNameOrdinals=(DWORD)FileBufferAddressToRva(pFileBuffer,(DWORD)newFileAddressOfNameOrdinals);
	newExportDirectoryAddr->AddressOfNames=(DWORD)FileBufferAddressToRva(pFileBuffer,(DWORD)newFileAddressOfNames);

	//�޸�Ŀ¼��
	pDataDirectory->VirtualAddress=(DWORD)FileBufferAddressToRva(pFileBuffer,(DWORD)newExportDirectoryAddr);


	return;

}