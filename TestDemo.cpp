#include "ShowPE.h"

#define FILEPATH_IN      "TestWin32Out.exe"              //�����ļ�·��
#define FILEPATH_OUT     "TestWin32Out.exe"             //����ļ�·��
#define SHELLCODELENGTH   0x12                          //ShellCode����
#define MESSAGEBOXADDR    0x76DAFDAE                    //MessageBox��ַ��ÿ�ο�������仯
#define SECTIONNUM        0x7;                          //Ҫ���ĸ�Ŀ��Section��Ӵ�����

//ҪǶ��Ĵ���
BYTE shellCode[]={
	0x6A,0x0,0x6A,0x0,0x6A,0x0,0x6A,0x0,
	0xE8,0x0,0x0,0x0,0x0,
	0xE9,0x0,0x0,0x0,0x0
};


void testPrinter(){
		//��ʼ��
	char* pathName=FILEPATH_IN;

	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;

	if(!ReadPEFile(pathName,&pFileBuffer)){
		return;
	}
		
		//��ӡDosHeader
		PrintDosHeaders(pFileBuffer);

		//��ӡNTHeader
		PrintNTHeaders(pFileBuffer);

		//��ӡPEheader
		PrintPEHeaders(pFileBuffer);

		//��ӡ��ѡ��PEͷ
		PrintOptionHeaders(pFileBuffer);
		
		//��ӡ�ڱ���Ϣ
		PrintSectionHeaders(pFileBuffer);

			




}

void testCopyFile(){
		//��ʼ��
	char* pathName=FILEPATH_IN;
	char* pathNameDes=FILEPATH_OUT;


	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;

	if(!ReadPEFile(pathName,&pFileBuffer)){
		return;
	}

	DWORD copySize=0;

	copySize= CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
	freePBuffer(pFileBuffer);
	
		
	if(!copySize){
		printf("CopyFileBufferToImageBuffer Failed!\n");	
		return;
	}
	
	copySize=CopyImageBufferToNewBuffer(pImageBuffer,&pNewFileBuffer);
	freePBuffer(pImageBuffer);

	if(!copySize){
		printf("CopyImageBufferToNewBuffer Failed!\n");
		return;
	}
	
	copySize=MemeryTOFile(pNewFileBuffer,copySize,pathNameDes);
	freePBuffer(pNewFileBuffer);

	if(!copySize){
		printf("MemeryTOFile Failed!\n");
		return;
	}

	
	}
	

void testRvaToFileOffset(){
	//��ʼ��
	char* pathName=FILEPATH_IN;

	LPVOID pFileBuffer=NULL;

	if(!ReadPEFile(pathName,&pFileBuffer)){
		return;
	}


	DWORD fileOffset=RvaToFileOffset(pFileBuffer,0x401480);

	printf("%X\n",fileOffset);


	
}

void testFileOffsetToRva(){
	//��ʼ��
	char* pathName=FILEPATH_IN;

	LPVOID pFileBuffer=NULL;

	if(!ReadPEFile(pathName,&pFileBuffer)){
		return;
	}
		
	
	DWORD RVA=FileOffsetToRva(pFileBuffer,0x21f92);

	printf("%X\n",RVA);

	
}

//��define�ж���ı�����MessageBox�������뵽ָ��Section�У�����ʱ����MessageBox��Ȼ����������FILEPATH_INԭ���Ĵ���
void testAddCodeIntoSection(){
	char* pathName=FILEPATH_IN;
	char* pathNameDes=FILEPATH_OUT;
	PBYTE pshellCode=shellCode;
	DWORD shellCodeLength=SHELLCODELENGTH;
	WORD sectionNum=SECTIONNUM;
	DWORD messageBoxAddress=MESSAGEBOXADDR;
	
	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;

	//FileToFileBuffer
	if(!ReadPEFile(pathName,&pFileBuffer)){
		return ;
	}

	DWORD copySize=0;

	//FileBufferToImageBuffer
	copySize= CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
	freePBuffer(pFileBuffer);
	if(!copySize){
		freePBuffer(pFileBuffer);
		printf("addShellCodeIntoSection---CopyFileBufferToImageBuffer Failed!\n");	
		return ;
	}
	
	PIMAGE_SECTION_HEADER pSectionHeader=getSection(pImageBuffer,sectionNum);
	
	if(!pSectionHeader){
			
		freePBuffer(pImageBuffer);
		printf("addShellCodeIntoSection Failed!---SectionNum:%d ������\n",sectionNum);	
		return ;
	}

	if(!checkSectionHeaderCouldWriteCode(pSectionHeader,shellCodeLength)){
			
		freePBuffer(pImageBuffer);
		printf("addShellCodeIntoSection Failed!---Section:%d û���㹻�Ŀռ���shellCode\n",sectionNum);
		return;
	}

	
	PBYTE pcodeBegin=NULL;
	pcodeBegin=getCodeBeginFromImageBuffer(pImageBuffer,pSectionHeader);
	
	//��shellCode���Ƶ�ImageBuffer��Ӧsection��
	memcpy(pcodeBegin,pshellCode,shellCodeLength);

	//����E8��ֵ
	DWORD E8RumTimeAddress= changeImageBufferAddressToRunTimeAddress(pImageBuffer,(DWORD)pcodeBegin+8);
	DWORD callAddress=changeE8E9AddressFromRunTimeBuffer(E8RumTimeAddress,messageBoxAddress);
	
	*(PDWORD)(pcodeBegin+9)=callAddress;

	//��ȡ�������
	PBYTE entryPos=getEntryRunTimeAddress(pImageBuffer);
	
	//����E9��ֵ
	DWORD E9RumTimeAddress= changeImageBufferAddressToRunTimeAddress(pImageBuffer,(DWORD)pcodeBegin+0xD);
	DWORD jmpAddress=changeE8E9AddressFromRunTimeBuffer(E9RumTimeAddress,(DWORD)entryPos);
	
	*(PDWORD)(pcodeBegin+0xE)=jmpAddress;

	//�޸�SectionȨ��Ϊ�ɶ���д��ִ��
	DWORD changeSectionCharacteristicsResult=changeSectionCharacteristics(pImageBuffer,sectionNum,0x60000020);
	if(!changeSectionCharacteristicsResult){
		printf("changeSectionCharacteristics Failed\n");
	}

	//�޸�PE����ڵ�ַ
	changeEntryPosByImageBufferAddress(pImageBuffer,(DWORD)pcodeBegin);

	
	
	LPVOID pNewBuffer=NULL;
	
	
	copySize=CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	
	freePBuffer(pImageBuffer);

	if(!copySize){
		printf("CopyImageBufferToNewBuffer Failed!\n");
		return;
	}

	copySize=MemeryTOFile(pNewBuffer,copySize,pathNameDes);
	freePBuffer(pNewFileBuffer);

	if(!copySize){
		printf("MemeryTOFile Failed!\n");
		return;
	}

}

//����һ����
void testAddNewSection(){
	char* pathName=FILEPATH_IN;
	char* pathNameDes=FILEPATH_OUT;
	DWORD sizeOfNewSection=5000;
	DWORD characteristics=0x60000020;

	
	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewImageBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;

	//FileToFileBuffer
	if(!ReadPEFile(pathName,&pFileBuffer)){
		return ;
	}

	DWORD copySize=0;

	//FileBufferToImageBuffer
	copySize= CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
	freePBuffer(pFileBuffer);
	if(!copySize){
		
		printf("addShellCodeIntoSection---CopyFileBufferToImageBuffer Failed!\n");	
		return ;
	}


	//����NTHeader��SectionHeaders
	copySize=topPENTAndSectionHeader(pImageBuffer);
	printf("topPENTHeader---%d\n",copySize);

	//����Ƿ����㹻�ռ���ӽڱ�
	DWORD checkCanAddSectionFlag=checkCanAddSection(pImageBuffer);

	if(!checkCanAddSectionFlag){
		freePBuffer(pImageBuffer);
		printf("checkCanAddSection---û���㹻�Ŀռ���ӽڱ�\n");

	}

	//����һ����
	DWORD checkAddNewSectionFlag=addNewSection(pImageBuffer,sizeOfNewSection,characteristics,&pNewImageBuffer);
	
	freePBuffer(pImageBuffer);

	if(!checkAddNewSectionFlag){
		printf("addNewSection Failed!\n");
		return;
	}
	
	

	copySize=CopyImageBufferToNewBuffer(pNewImageBuffer,&pNewFileBuffer);
	
	freePBuffer(pNewImageBuffer);

	if(!copySize){
		printf("CopyImageBufferToNewBuffer Failed!\n");
		return;
	}

	copySize=MemeryTOFile(pNewFileBuffer,copySize,pathNameDes);
	freePBuffer(pNewFileBuffer);

	if(!copySize){
		printf("MemeryTOFile Failed!\n");
		return;
	}

	return;
}

//�������һ��Section
void testExtendTheLastSection(){
	char* pathName=FILEPATH_IN;
	char* pathNameDes=FILEPATH_OUT;
	DWORD addSizeNew=5000;


	
	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewImageBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;

	//FileToFileBuffer
	if(!ReadPEFile(pathName,&pFileBuffer)){
		return ;
	}

	DWORD copySize=0;

	//FileBufferToImageBuffer
	copySize= CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
	freePBuffer(pFileBuffer);
	if(!copySize){
		
		printf("addShellCodeIntoSection---CopyFileBufferToImageBuffer Failed!\n");	
		return ;
	}


	//�������һ������
	DWORD checkExtendLastSection=extendTheLastSection(pImageBuffer,addSizeNew,&pNewImageBuffer);
	
	freePBuffer(pImageBuffer);

	if(!checkExtendLastSection){
		printf("extendLastSection Failed!\n");
		return;
	}
	
	

	copySize=CopyImageBufferToNewBuffer(pNewImageBuffer,&pNewFileBuffer);
	
	freePBuffer(pNewImageBuffer);

	if(!copySize){
		printf("CopyImageBufferToNewBuffer Failed!\n");
		return;
	}

	copySize=MemeryTOFile(pNewFileBuffer,copySize,pathNameDes);
	freePBuffer(pNewFileBuffer);

	if(!copySize){
		printf("MemeryTOFile Failed!\n");
		return;
	}

	return;
}


int main(int argc, char* argv[]){

	//testPrinter();
	//testCopyFile();
	//testRvaToFileOffset();
	//testFileOffsetToRva();
	//testAddCodeIntoSection();
	//testAddNewSection();
	testExtendTheLastSection();
	return 0;
}

