#include "ShowPE.h"

#define FILEPATH_IN      "DialogFirst.exe"                         // "D:\\VCWorkspace\\TestDll\\Debug\\TestDll.dll"              //输入文件路径
#define FILEPATH_OUT     "TestWin32Out.exe"             //输出文件路径
#define SHELLCODELENGTH   0x12                          //ShellCode长度
#define MESSAGEBOXADDR    0x7469FDAE                   //MessageBox地址，每次开机都会变化
#define SECTIONNUM        0x6;                          //要向哪个目标Section添加代码了

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
		//PrintRelocationTable(pFileBuffer);

		//打印导入表
		//PrintImportTable(pFileBuffer);

		//打印绑定导入表
		//PrintBoundImportTable(pFileBuffer);

		//打印资源表
		PrintResourceTable(pFileBuffer);

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

//按define中定义的变量将MessageBox函数插入到指定Section(Section的virtualSize<sizeOfRawdata)中，运行时弹出MessageBox，然后正常运行FILEPATH_IN原来的代码
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

//按FileBuffer扩大最后一个Section
void testExtendTheLastSectionByFileBuffer(){
	char* pathName=FILEPATH_IN;
	char* pathNameDes=FILEPATH_OUT;
	DWORD addSizeNew=9000;
	
	//一般设置这个权限0x60000020; 只有一个节的情况下设置这个权限0xE0000060;
	DWORD characteristics=0xE0000060;

	
	LPVOID pFileBuffer=NULL;

	LPVOID pNewFileBuffer=NULL;

	DWORD copySize=0;
	//FileToFileBuffer
	if(!ReadPEFile(pathName,&pFileBuffer)){
		return ;
	}





	//扩大最后一个节了
	DWORD checkExtendLastSection=extendTheLastSectionByFileBuffer(pFileBuffer,addSizeNew,characteristics,&pNewFileBuffer);
	
	freePBuffer(pFileBuffer);

	if(!checkExtendLastSection){
		printf("extendLastSection Failed!\n");
		return;
	}
	
	copySize=getFileBufferSize(pNewFileBuffer);

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



	return;

}

//测试移动重定位表
void testRemoveRelocationDirectory(){
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
	addSize=getRelocationDirectorySize(pFileBuffer);

	
	//新增一个节
	DWORD fileRVA=addNewSectionByFileBuffer(pFileBuffer,addSize,characteristics,&pNewFileBuffer);
	
	freePBuffer(pFileBuffer);


	if(!fileRVA){
		printf("addNewSection Failed!\n");
		return;
	}
	
	
	//移动重定位表
	removeRelocationDirectory(pNewFileBuffer,fileRVA);


	copySize=getFileBufferSize(pNewFileBuffer);

	copySize=MemeryTOFile(pNewFileBuffer,copySize,pathNameDes);
	freePBuffer(pNewFileBuffer);

	if(!copySize){
		printf("MemeryTOFile Failed!\n");
		return;
	}


	return;

}

//修改DLL的ImageBase,根据重定位表修正，然后存盘.看DLL是否可以使用.
VOID testChangeImageBase(DWORD newImageBase)
{
	char* pathName=FILEPATH_IN;
	char* pathNameDes=FILEPATH_OUT;
	

	
	LPVOID pFileBuffer=NULL;



	//FileToFileBuffer
	if(!ReadPEFile(pathName,&pFileBuffer)){
		return ;
	}

	DWORD copySize=0;

	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	DWORD imageBase = pOptionHeader->ImageBase;

	DWORD gapImageBase=0;

	if(imageBase>newImageBase){
		gapImageBase=imageBase-newImageBase;
	}else{
		gapImageBase=newImageBase-imageBase;
	}

	pOptionHeader->ImageBase=newImageBase;

	printf("%x,%x\n",pOptionHeader->ImageBase,newImageBase);

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,6);
	//获得重定位表在FileBuffer中的Address位置
	DWORD relocationFileBufferAddress =RvaToFileBufferAddress(pFileBuffer,pDataDirectory->VirtualAddress);
	
	//找到重定位表位置
	PIMAGE_BASE_RELOCATION pRelocationTables=(PIMAGE_BASE_RELOCATION)relocationFileBufferAddress;

	while(pRelocationTables->VirtualAddress)
	{
	
		DWORD sizeOfBlock=pRelocationTables->SizeOfBlock;
		DWORD virtualAddress=pRelocationTables->VirtualAddress;
		
		
		//修改每个重定位表指向的地址
		//printf("***表:%d\tsizeOfBlock:%d\tvirtualAddress:%X\tsectionIndex:%d\n",i,sizeOfBlock,virtualAddress,sectionIndex);
		//计算BLOCK的数量
		DWORD numBlock=0;
		numBlock=(sizeOfBlock-8)/2;
		
		DWORD j=0;
		PWORD pStartBlock=(PWORD)pRelocationTables+4;
		for(j=0;j<numBlock;j++)
		{
			//硬编码地方的地址
			DWORD rvaChange=(DWORD)((*(PWORD)pStartBlock)&0x0FFF)+virtualAddress;
			DWORD isChange=(*(PWORD)pStartBlock)&0xF000;
			PDWORD fileBufferAddress=(PDWORD)RvaToFileBufferAddress(pFileBuffer,rvaChange);
		
			if((isChange^0x3000)==0){
				if(imageBase>newImageBase){
					*fileBufferAddress-=gapImageBase;
					
				}else{
					*fileBufferAddress+=gapImageBase;
				}
			}
			

		
	
			pStartBlock++;

		}
		

		//下一个重定位表地址
		pRelocationTables=(PIMAGE_BASE_RELOCATION)((char*)pRelocationTables+sizeOfBlock);


	}

	

	copySize=getFileBufferSize(pFileBuffer);

	copySize=MemeryTOFile(pFileBuffer,copySize,pathNameDes);
	freePBuffer(pFileBuffer);

	if(!copySize){
		printf("MemeryTOFile Failed!\n");
		return;
	}


	return;


}	

//测试注入导入表
void testInjectImportDirectory(){
	char* pathName=FILEPATH_IN;
	char* dllPathName="InjectDll.dll";
	char* pathNameDes=FILEPATH_OUT;
	//一般设置这个权限0x60000020; 只有一个节的情况下设置这个权限0xE0000060;
	DWORD characteristics=0xE0000060;

	char* pFunName="ExportFunction";//要注入的导入表名称

	char* pDllName=NULL;//Dll表名称

	DWORD addSizeNew=0;
	

//获得Dll文件的信息
//pFileInputPath 文件的路径
//pFunName 导入表函数名
//pDllNames,输出Dll文件的名字
   addSizeNew = getDllExportInfor(dllPathName,pFunName,&pDllName);
	
	

	
	LPVOID pFileBuffer=NULL;

	LPVOID pNewFileBuffer=NULL;

	DWORD copySize=0;

	//FileToFileBuffer
	if(!ReadPEFile(pathName,&pFileBuffer)){
		return ;
	}

	DWORD imageImportDescriptorsSize=getImageImportDescriptorsSize(pFileBuffer);

	addSizeNew+=imageImportDescriptorsSize;

	//扩大最后一个节了
	DWORD fileRVA=extendTheLastSectionByFileBuffer(pFileBuffer,addSizeNew,characteristics,&pNewFileBuffer);

	freePBuffer(pFileBuffer);

	fileRVA=removeImportDirectory(pNewFileBuffer,fileRVA,imageImportDescriptorsSize);

	
	//新增一个导入表
	PIMAGE_IMPORT_DESCRIPTOR pNewImportDirectory=(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pNewFileBuffer+fileRVA);

	//获得最后一个导入表
	PIMAGE_IMPORT_DESCRIPTOR pLastImportDirectory=pNewImportDirectory-1;

	*pNewImportDirectory=*pLastImportDirectory;
	
	PIMAGE_IMPORT_DESCRIPTOR pLastNullImportDirectory=pNewImportDirectory+1;
	pLastNullImportDirectory->Characteristics=0;
	pLastNullImportDirectory->FirstThunk=0;
	pLastNullImportDirectory->ForwarderChain=0;
	pLastNullImportDirectory->Name=0;
	pLastNullImportDirectory->OriginalFirstThunk=0;
	pLastNullImportDirectory->TimeDateStamp=0;

	
	//获得新增的INT表首地址了
	PIMAGE_THUNK_DATA32 pINT=(PIMAGE_THUNK_DATA32)(pNewImportDirectory+2);

	//设置新增节的OriginalFirstThunk
	pNewImportDirectory->OriginalFirstThunk=FileBufferAddressToRva(pNewFileBuffer,(DWORD)pINT);
	
	*(PDWORD)(pINT+1)=0;

	//获得新增的IAT表首地址了
	PIMAGE_THUNK_DATA32 pIAT=pINT+2;
	
	//设置新增节的FirstThunk
	pNewImportDirectory->FirstThunk=FileBufferAddressToRva(pNewFileBuffer,(DWORD)pIAT);

	*(PDWORD)(pIAT+1)=0;
	
	//设置新增的ImageImportByName
	PIMAGE_IMPORT_BY_NAME pImageImportByName=(PIMAGE_IMPORT_BY_NAME)(pIAT+2);

	pImageImportByName->Hint=0;

	strcpy((char*)(pImageImportByName->Name),pFunName);
	

	//将INT和IAT表指向ImageImportByName表
	*(PDWORD)pINT=FileBufferAddressToRva(pNewFileBuffer,(DWORD)pImageImportByName);

	*(PDWORD)pIAT=*(PDWORD)pINT;

	//新增dll名称
	char* pDllNameAdd=(char*)(pImageImportByName+1)+strlen(pFunName);
	strcpy(pDllNameAdd,pDllName);
	
	pNewImportDirectory->Name=FileBufferAddressToRva(pNewFileBuffer,(DWORD)pDllNameAdd);
	
	copySize=getFileBufferSize(pNewFileBuffer);
	
	
	copySize=MemeryTOFile(pNewFileBuffer,copySize,pathNameDes);
	freePBuffer(pNewFileBuffer);

	if(!copySize){
		printf("MemeryTOFile Failed!\n");
		return;
	}

	return;

}



int main(int argc, char* argv[]){

	testPrinter();
	//testCopyFile();
	//testRvaToFileOffset();
	//testFileOffsetToRva();
	//testAddressChangeByFileBufferAndRva();
	//testAddCodeIntoSection();
	//testAddNewSection();
	//testAddNewSectionByFileBuffer();
	//testExtendTheLastSection();
	//testExtendTheLastSectionByFileBuffer();
	//testMergeAllSections();
	//testExportDirectory();
	//testRemoveExportDirectory();
	//testRemoveRelocationDirectory();
	//testChangeImageBase(0x500000);
	//testInjectImportDirectory();

	return 0;
}

