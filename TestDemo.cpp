#include "ShowPE.h"

#define FILEPATH_IN      "TestWin32.exe"                //输入文件路径
#define FILEPATH_OUT     "TestWin32Out.exe"             //输出文件路径
#define SHELLCODELENGTH   0x12                          //ShellCode长度
#define MESSAGEBOXADDR    0x755AFDAE                    //MessageBox地址，每次开机都会变化
#define SECTIONNUM        0x5;                          //要向哪个目标Section添加代码了

//要嵌入的代码
BYTE shellCode[]={
	0x6A,0x0,0x6A,0x0,0x6A,0x0,0x6A,0x0,
	0xE8,0x0,0x0,0x0,0x0,
	0xE9,0x0,0x0,0x0,0x0
};


void testPrinter(){
		//初始化
	char* pathName=FILEPATH_IN;

	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;

	if(!ReadPEFile(pathName,&pFileBuffer)){
		return;
	}
		
		//打印DosHeader
		PrintDosHeaders(pFileBuffer);

		//打印NTHeader
		PrintNTHeaders(pFileBuffer);

		//打印PEheader
		PrintPEHeaders(pFileBuffer);

		//打印可选的PE头
		PrintOptionHeaders(pFileBuffer);
		
		//打印节表信息
		PrintSectionHeaders(pFileBuffer);

			




}

void testCopyFile(){
		//初始化
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
	//初始化
	char* pathName=FILEPATH_IN;

	LPVOID pFileBuffer=NULL;

	if(!ReadPEFile(pathName,&pFileBuffer)){
		return;
	}


	DWORD fileOffset=RvaToFileOffset(pFileBuffer,0x401480);

	printf("%X\n",fileOffset);


	
}

void testFileOffsetToRva(){
	//初始化
	char* pathName=FILEPATH_IN;

	LPVOID pFileBuffer=NULL;

	if(!ReadPEFile(pathName,&pFileBuffer)){
		return;
	}
		
	
	DWORD RVA=FileOffsetToRva(pFileBuffer,0x21f92);

	printf("%X\n",RVA);

	
}

//按define中定义的变量将MessageBox函数插入到指定Section中，运行时弹出MessageBox，然后正常运行FILEPATH_IN原来的代码
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

	if(!copySize){
		freePBuffer(pFileBuffer);
		printf("addShellCodeIntoSection---CopyFileBufferToImageBuffer Failed!\n");	
		return ;
	}
	
	PIMAGE_SECTION_HEADER pSectionHeader=getSection(pFileBuffer,sectionNum);
	
	if(!pSectionHeader){
		freePBuffer(pFileBuffer);	
		freePBuffer(pImageBuffer);
		printf("addShellCodeIntoSection Failed!---SectionNum:%d 不存在\n",sectionNum);	
		return ;
	}

	if(!checkSectionHeaderCouldWriteCode(pSectionHeader,shellCodeLength)){
		freePBuffer(pFileBuffer);	
		freePBuffer(pImageBuffer);
		printf("addShellCodeIntoSection Failed!---Section:%d 没有足够的空间存放shellCode\n",sectionNum);
		return;
	}


	PBYTE pcodeBegin=NULL;
	pcodeBegin=getCodeBeginFromImageBuffer(pImageBuffer,pSectionHeader);
	
	//将shellCode复制到ImageBuffer对应section中
	memcpy(pcodeBegin,pshellCode,shellCodeLength);

	//修正E8的值
	DWORD E8RumTimeAddress= changeImageBufferAddressToRunTimeAddress(pImageBuffer,(DWORD)pcodeBegin+8);
	DWORD callAddress=changeE8E9AddressFromRunTimeBuffer(E8RumTimeAddress,messageBoxAddress);
	
	*(PDWORD)(pcodeBegin+9)=callAddress;

	//获取程序入口
	PBYTE entryPos=getEntryRunTimeAddress(pImageBuffer);
	
	//修正E9的值
	DWORD E9RumTimeAddress= changeImageBufferAddressToRunTimeAddress(pImageBuffer,(DWORD)pcodeBegin+0xD);
	DWORD jmpAddress=changeE8E9AddressFromRunTimeBuffer(E9RumTimeAddress,(DWORD)entryPos);
	
	*(PDWORD)(pcodeBegin+0xE)=jmpAddress;

	//修改Section权限为可读可写可执行
	DWORD changeSectionCharacteristicsResult=changeSectionCharacteristics(pImageBuffer,sectionNum,0x60000020);
	if(!changeSectionCharacteristicsResult){
		printf("changeSectionCharacteristics Failed\n");
	}

	//修改PE的入口地址
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

int main(int argc, char* argv[]){

	//testPrinter();
	//testCopyFile();
	//testRvaToFileOffset();
	//testFileOffsetToRva();
	testAddCodeIntoSection();
	return 0;
}

