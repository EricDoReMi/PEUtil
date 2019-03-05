#include "ShowPE.h"

#define FILEPATH_IN      "D:\\VCWorkspace\\TestDll\\Debug\\TestDll.dll"                         // "D:\\VCWorkspace\\MyTest\\TestDefDll.dll"              //输入文件路径
#define FILEPATH_OUT     "TestDllNew.dll"             //输出文件路径
#define SHELLCODELENGTH   0x12                          //ShellCode长度
#define MESSAGEBOXADDR    0x7720FDAE                   //MessageBox地址，每次开机都会变化
#define SECTIONNUM        0x1;                          //要向哪个目标Section添加代码了

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
		/*PrintDosHeaders(pFileBuffer);

		//打印NTHeader
		PrintNTHeaders(pFileBuffer);

		//打印PEheader
		PrintPEHeaders(pFileBuffer);

		//打印可选的PE头
		PrintOptionHeaders(pFileBuffer);
		
		//打印节表信息
		PrintSectionHeaders(pFileBuffer);

		//打印目录表
	    PrintDataDirectory(pFileBuffer);*/

		//打印导出表
		//PrintExportTable(pFileBuffer);

		//打印重定向表
		PrintRelocationTable(pFileBuffer);

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


	DWORD fileOffset=RvaToFileOffset(pFileBuffer,0x32000);
	

	printf("%X\n",fileOffset);


	
}

void testFileOffsetToRva(){
	//初始化
	char* pathName=FILEPATH_IN;

	LPVOID pFileBuffer=NULL;

	if(!ReadPEFile(pathName,&pFileBuffer)){
		return;
	}
		
	
	DWORD RVA=FileOffsetToRva(pFileBuffer,0x32000);
	

	printf("%X\n",RVA);

	
}

//测试FileBuffer和RVA地址间的相互转换
void testAddressChangeByFileBufferAndRva(){
		//初始化
	char* pathName=FILEPATH_IN;

	LPVOID pFileBuffer=NULL;

	if(!ReadPEFile(pathName,&pFileBuffer)){
		return;
	}
	
	DWORD fileBufferAddress=RvaToFileBufferAddress(pFileBuffer,0x2DF10);
	printf("fileBufferAddress:%X\n",fileBufferAddress);

	DWORD RVA=FileBufferAddressToRva(pFileBuffer,fileBufferAddress);

	printf("RVA:%X\n",RVA);
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
	freePBuffer(pFileBuffer);
	if(!copySize){
		freePBuffer(pFileBuffer);
		printf("addShellCodeIntoSection---CopyFileBufferToImageBuffer Failed!\n");	
		return ;
	}
	
	PIMAGE_SECTION_HEADER pSectionHeader=getSection(pImageBuffer,sectionNum);
	
	if(!pSectionHeader){
			
		freePBuffer(pImageBuffer);
		printf("addShellCodeIntoSection Failed!---SectionNum:%d 不存在\n",sectionNum);	
		return ;
	}

	if(!checkSectionHeaderCouldWriteCode(pSectionHeader,shellCodeLength)){
			
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
	//一般设置这个权限0x60000020; 只有一个节的情况下设置这个权限0xE0000060;
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

//新增一个节
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


	//上移NTHeader和SectionHeaders
	copySize=topPENTAndSectionHeader(pImageBuffer);
	printf("topPENTHeader---%d\n",copySize);

	//检查是否有足够空间添加节表
	DWORD checkCanAddSectionFlag=checkCanAddSection(pImageBuffer);

	if(!checkCanAddSectionFlag){
		freePBuffer(pImageBuffer);
		printf("checkCanAddSection---没有足够的空间添加节表\n");

	}

	//新增一个节
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

//直接在FileBuffer中新增一个节
void testAddNewSectionByFileBuffer(){
	char* pathName=FILEPATH_IN;
	char* pathNameDes=FILEPATH_OUT;
	DWORD sizeOfNewSection=5000;
	DWORD characteristics=0x60000020;

	
	LPVOID pFileBuffer=NULL;

	LPVOID pNewFileBuffer=NULL;
	
	DWORD copySize=0;
	copySize=ReadPEFile(pathName,&pFileBuffer);

	//FileToFileBuffer
	if(!copySize){
		return ;
	}



	//上移NTHeader和SectionHeaders
	copySize=topPENTAndSectionHeader(pFileBuffer);
	printf("topPENTHeader---%d\n",copySize);

	//检查是否有足够空间添加节表
	DWORD checkCanAddSectionFlag=checkCanAddSection(pFileBuffer);

	if(!checkCanAddSectionFlag){
		freePBuffer(pFileBuffer);
		printf("checkCanAddSection---没有足够的空间添加节表\n");
		return;

	}

	//新增一个节
	DWORD fileRVA=addNewSectionByFileBuffer(pFileBuffer,sizeOfNewSection,characteristics,&pNewFileBuffer);
	
	freePBuffer(pFileBuffer);

	if(!fileRVA){
		printf("addNewSection Failed!\n");
		return;
	}
	
	
	copySize=getFileBufferSize(pNewFileBuffer);

	copySize=MemeryTOFile(pNewFileBuffer,copySize,pathNameDes);
	freePBuffer(pNewFileBuffer);

	if(!copySize){
		printf("MemeryTOFile Failed!\n");
		return;
	}

	printf("新增节RVA:%X\n",fileRVA);

	return;

}

//扩大最后一个Section
void testExtendTheLastSection(){
	char* pathName=FILEPATH_IN;
	char* pathNameDes=FILEPATH_OUT;
	DWORD addSizeNew=5000;
	
	//一般设置这个权限0x60000020; 只有一个节的情况下设置这个权限0xE0000060;
	DWORD characteristics=0xE0000060;

	
	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewImageBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;

	DWORD copySize=0;
	//FileToFileBuffer
	if(!ReadPEFile(pathName,&pFileBuffer)){
		return ;
	}



	//FileBufferToImageBuffer
	copySize= CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
	freePBuffer(pFileBuffer);
	if(!copySize){
		
		printf("addShellCodeIntoSection---CopyFileBufferToImageBuffer Failed!\n");	
		return ;
	}


	//扩大最后一个节了
	DWORD checkExtendLastSection=extendTheLastSection(pImageBuffer,addSizeNew,characteristics,&pNewImageBuffer);
	
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


//合并所有的Section
void testMergeAllSections(){
	char* pathName=FILEPATH_IN;
	char* pathNameDes=FILEPATH_OUT;

	DWORD characteristics=0xE0000060;//0x60000060或0xE0000060

	
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


	//合并所有的节
	DWORD checkMergeAllSections=mergeAllSections(pImageBuffer,characteristics,&pNewImageBuffer);
	
	freePBuffer(pImageBuffer);

	if(!checkMergeAllSections){
		printf("checkMergeAllSections Failed!\n");
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

//测试导出表地址转换
void testExportDirectory()
{
	char* pathName=FILEPATH_IN;

	
	LPVOID pFileBuffer=NULL;


	//FileToFileBuffer
	if(!ReadPEFile(pathName,&pFileBuffer)){
		return ;
	}

	int a=8;
	int b=9;
	char* funName="Plus";

	int (*lpPlus)(int,int);
	int (*lpSub)(int,int);


	lpPlus=(int(*)(int,int)) ((DWORD)pFileBuffer+GetFunctionRVAByName(pFileBuffer,funName));
	
	lpSub=(int(*)(int,int)) ((DWORD)pFileBuffer+(DWORD)GetFunctionRVAByOrdinals(pFileBuffer,15));
	
	printf("PlusResultAddr:%X\n",lpPlus);
	printf("SubsResultAddr:%X\n",lpSub);

}

//测试移动导出表
void testRemoveExportDirectory(){
	char* pathName=FILEPATH_IN;
	char* pathNameDes=FILEPATH_OUT;
	DWORD characteristics=0x60000020;

	
	LPVOID pFileBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;


	//FileToFileBuffer
	if(!ReadPEFile(pathName,&pFileBuffer)){
		return ;
	}

	DWORD copySize=0;
	//上移NTHeader和SectionHeaders
	copySize=topPENTAndSectionHeader(pFileBuffer);
	printf("topPENTHeader---%d\n",copySize);

	//检查是否有足够空间添加节表
	DWORD checkCanAddSectionFlag=checkCanAddSection(pFileBuffer);

	if(!checkCanAddSectionFlag){
		freePBuffer(pFileBuffer);
		printf("checkCanAddSection---没有足够的空间添加节表\n");
		return;

	}

	DWORD addSize=0;
	addSize=getExportDirectorySize(pFileBuffer);

	
	//新增一个节
	DWORD fileRVA=addNewSectionByFileBuffer(pFileBuffer,addSize,characteristics,&pNewFileBuffer);
	
	freePBuffer(pFileBuffer);


	if(!fileRVA){
		printf("addNewSection Failed!\n");
		return;
	}
	
	
	//移动导出表

	removeExportDirectory(pNewFileBuffer,fileRVA);


	copySize=getFileBufferSize(pNewFileBuffer);

	copySize=MemeryTOFile(pNewFileBuffer,copySize,pathNameDes);
	freePBuffer(pNewFileBuffer);

	if(!copySize){
		printf("MemeryTOFile Failed!\n");
		return;
	}

	printf("新增节RVA:%X\n",fileRVA);

	return;

}

int main(int argc, char* argv[]){

	//testPrinter();
	//testCopyFile();
	//testRvaToFileOffset();
	//testFileOffsetToRva();
	//testAddressChangeByFileBufferAndRva();
	//testAddCodeIntoSection();
	//testAddNewSection();
	//testAddNewSectionByFileBuffer();
	//testExtendTheLastSection();
	//testMergeAllSections();
	//testExportDirectory();
	testRemoveExportDirectory();
	return 0;
}

