#include "PEUtil.h"


//获取文件大小
int getFileSize(FILE *P_file){
	int filesize=0;
	if(P_file){
		fseek(P_file,0,SEEK_END);
		filesize=ftell(P_file);
		fseek(P_file, 0, SEEK_SET);
	}else{
		printf("getFileSize Failed---文件指针为NULL");
	}
	return filesize;
}

//读取到FileBuffer
//return 0 失败 1 成功
//函数声明							
//**************************************************************************							
//ReadPEFile:将文件读取到缓冲区							
//参数说明：							
//lpszFile 文件路径							
//pFileBuffer 缓冲区指针							
//返回值说明：							
//读取失败返回0  否则返回实际读取的大小							
//**************************************************************************							
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer)		
{		
	FILE *pFile = NULL;	
	DWORD fileSize = 0;	
	LPVOID pFileBufferTmp=NULL;
		
	//打开文件	
    pFile = fopen(lpszFile, "rb");		
	if(!pFile)	
	{	
		printf("ReadPEFile Failed---无法打开EXE 文件,%s!\n",lpszFile);
		return 0;
	}	
    //读取文件大小		

    fileSize = getFileSize(pFile);		

	//分配缓冲区	
	pFileBufferTmp = malloc(fileSize);	
		
	if(!pFileBufferTmp)	
	{	
		printf("ReadPEFile  Failed---读取PE文件后分配空间失败%s!\n",lpszFile);
		fclose(pFile);
		pFile=NULL;
		return 0;
	}	

	memset(pFileBufferTmp,0,fileSize);

	//将文件数据读取到缓冲区	
	DWORD n = (DWORD)fread(pFileBufferTmp, fileSize, 1, pFile);	
	if(!n)	
	{	
		printf("ReadPEFile Failed---读取PE文件数据失败,%s!\n",lpszFile);
		free(pFileBufferTmp);
		fclose(pFile);
		pFile=NULL;
		pFileBufferTmp=NULL;
		return 0;
	}	

	if(!checkIsPEFile(pFileBufferTmp)){
		printf("ReadPEFile Failed---不是标准PE文件,%s!\n",lpszFile);
		free(pFileBufferTmp);
		fclose(pFile);
		pFile=NULL;
		pFileBufferTmp=NULL;
		return 0;
	}
	//关闭文件	
	fclose(pFile);
	pFile=NULL;
	*pFileBuffer=pFileBufferTmp;
	printf("ReadPEFile successed,%s!\n",lpszFile);
    return fileSize;		
	
}

//**************************************************************************							
//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer							
//参数说明：							
//pFileBuffer  FileBuffer指针							
//pImageBuffer ImageBuffer指针							
//返回值说明：							
//读取失败返回0  否则返回复制的大小							
//**************************************************************************
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer){

	if(!checkIsPEFile(pFileBuffer)){
		printf("CopyFileBufferToImageBuffer Failed---pFileBuffer不是标准PE文件!\n");
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

		printf("CopyFileBufferToImageBuffer---malloc PImageBuffer失败!\n");

		return 0;
	}
	
	memset(pImageBufferTmp,0,sizeOfImage);

	//============将pFileBuffer数据读取到pImageBuffer中=========

	//读取Headers

	memcpy(pImageBufferTmp,pFileBuffer,POptionPEHeader->SizeOfHeaders);

	DWORD virtualAddress=0;
	DWORD sizeOfRawData=0;
	DWORD pointerToRawData=0;

	
	//根据节表中的信息循环将FileBuffer中的节拷贝到ImageBuffer中
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
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区，将ImageBuffer还原为文件的PE格式							
//参数说明：							
//pImageBuffer ImageBuffer指针							
//pNewBuffer NewBuffer指针							
//返回值说明：							
//读取失败返回0  否则返回复制的大小							
//**************************************************************************							
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer){
	if(!checkIsPEFile(pImageBuffer)){
		printf("CopyImageBufferToNewBuffer Failed---pImageBuffer不是标准PE文件!\n");
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

		printf("CopyImageBufferToNewBuffer---malloc pNewBufferTmp失败!\n ");
		
		return 0;
	}
	
	memset(pNewBufferTmp,0,sizeOfNewBuffer);
	
	//============将pImageBuffer数据读取到pNewBuffer中=========
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pImageBuffer);
	DWORD i=0;
	//读取Headers
	for(i=0;i<sizeOfHeaders;i++)
	{
		*((char*)pNewBufferTmp+i)=*((char*)pImageBuffer+i);
	}

	DWORD virtualAddress=0;
	DWORD sizeOfRawData=0;
	DWORD pointerToRawData=0;


	//根据节表中的信息循环将pImageBuffer中的节拷贝到pNewBuffer中
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
//MemeryTOFile:将内存中的数据复制到文件							
//参数说明：							
//pMemBuffer 内存中数据的指针							
//size 要复制的大小							
//lpszFile 要存储的文件路径							
//返回值说明：							
//读取失败返回0  否则返回复制的大小							
//**************************************************************************							
DWORD MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile){
	if(!checkIsPEFile(pMemBuffer)){
		printf("CopyImageBufferToNewBuffer Failed---pMemBuffer不是标准PE文件,%s!\n",lpszFile);
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
//RvaToFileOffset:将内存偏移转换为文件偏移							
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwRva RVA的值							
//返回值说明：							
//返回转换后的FOA的值  如果失败返回0							
//**************************************************************************							
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva){
	if(!checkIsPEFile(pFileBuffer)){
		printf("RvaToFileOffset Failed---pFileBuffer不是标准PE文件!\n");
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
			//找到了所在节的位置
			return dwRva-virtualAddress+(pSectionHeader->PointerToRawData);
			
		}
		
		pSectionHeader=pSectionHeader+1;
	}

	
	return 0;
}

//**************************************************************************							
//RvaToSectionIndex:通过内存偏移寻找sectionIndex							
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwRva RVA的值							
//返回值说明：							
//返回找到的SectionNum号 如果失败返回0							
//**************************************************************************							
DWORD RvaToSectionIndex(IN LPVOID pFileBuffer,IN DWORD dwRva){
	if(!checkIsPEFile(pFileBuffer)){
		printf("RvaToFileOffset Failed---pFileBuffer不是标准PE文件!\n");
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
			//找到了所在节的位置
			return indexSection;
			
		}
		
		pSectionHeader=pSectionHeader+1;
	}

	
	return 0;
}

//**************************************************************************							
//FileOffsetToRva:将文件偏移转换为内存偏移							
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwFileOffSet RVA的值							
//返回值说明：							
//返回转换后的RVA的值  如果失败返回0							
//**************************************************************************							
DWORD FileOffsetToRva(IN LPVOID pFileBuffer,IN DWORD dwFileOffSet){
	if(!checkIsPEFile(pFileBuffer)){
		printf("RvaToFileOffset Failed---pFileBuffer不是标准PE文件!\n");

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
			//找到了所在节的位置
			return virtualAddress+(dwFileOffSet-pointerToRawData);
			
		}
		
		pSectionHeader=pSectionHeader+1;
	}

	
	return 0;
}

//**************************************************************************							
//RvaToFileBufferAddress:将内存偏移转换为FileBuffer中的地址了							
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwRva RVA的值							
//返回值说明：							
//返回转换后的FileAddress的值  如果失败返回0							
//**************************************************************************							
DWORD RvaToFileBufferAddress(IN LPVOID pFileBuffer,IN DWORD dwRva){
	if(!checkIsPEFile(pFileBuffer)){
		printf("RvaToFileOffset Failed---pFileBuffer不是标准PE文件!\n");
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
			//找到了所在节的位置
			return ((DWORD)pFileBuffer+(dwRva-virtualAddress+(pSectionHeader->PointerToRawData)));
			
		}
		
		pSectionHeader=pSectionHeader+1;
	}

	
	return 0;
}

//**************************************************************************							
//FileBufferAddressToRva:将FileBuffer中的地址转换为内存偏移							
//参数说明：							
//pFileBuffer FileBuffer指针							
//dwFileAddress fileBuffer中地址						
//返回值说明：							
//返回转换后的RVA的值  如果失败返回0							
//**************************************************************************							
DWORD FileBufferAddressToRva(IN LPVOID pFileBuffer,IN DWORD dwFileAddress){
	if(!checkIsPEFile(pFileBuffer)){
		printf("RvaToFileOffset Failed---pFileBuffer不是标准PE文件!\n");

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
			//找到了所在节的位置
			return virtualAddress+(gapImageBase-pointerToRawData);
			
		}
		
		pSectionHeader=pSectionHeader+1;
	}

	
	return 0;
}

//释放Buffer
void freePBuffer(LPVOID pBuffer){
	
		free(pBuffer);
		pBuffer=NULL;
	
}

//检查是不是PE文件
//return 0 失败 1 成功
int checkIsPEFile(LPVOID pBuffer){
		//判断是否是有效的MZ标志	
	if(*((PWORD)pBuffer) != IMAGE_DOS_SIGNATURE)	
	{	
		printf("不是有效的MZ标志\n");
		
		return 0; 
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pBuffer);
		//判断是否是有效的PE标志	
	if(*((PDWORD)((DWORD)pBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)	
	{	
		
		printf("不是有效的PE标志\n");
		
		return 0;
	}
	
	return 1;
}

//获取Dos文件头
PIMAGE_DOS_HEADER getDosHeader(LPVOID pBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	return pDosHeader;
}

//获得NT文件头
PIMAGE_NT_HEADERS getNTHeader(LPVOID pBuffer){
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pBuffer);
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pBuffer+pDosHeader->e_lfanew);
	return pNTHeader;
}


//获得PE文件头
PIMAGE_FILE_HEADER getPEHeader(LPVOID pBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	pNTHeader=getNTHeader(pBuffer);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	return pPEHeader;
}


//获得可选的PE头
PIMAGE_OPTIONAL_HEADER32 getOptionHeader(LPVOID pBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pPEHeader = getPEHeader(pBuffer);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	return pOptionHeader;
}

//获得节表头
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

//获取节表了
//index 第几个节表
//返回值：成功返回该节表头，失败则返回NULL
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

//获得节的数量
WORD getSectionNum(LPVOID pBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader = getPEHeader(pBuffer);
	return pPEHeader->NumberOfSections;
}



//将ShellCode添加到某个Section中
//pathName:源文件路径
//pathNameDes:目标文件路径
//pshellCode:shellCode地址
//shellCodeLength:shellCode的长度
//sectionNum:节的地址了
//返回值:成功返回1,失败返回0
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
		printf("addShellCodeIntoSection Failed!---SectionNum:%d 不存在\n",sectionNum);	
		return 0;
	}

	if(!checkSectionHeaderCouldWriteCode(pSectionHeader,shellCodeLength)){
		freePBuffer(pFileBuffer);	
		freePBuffer(pImageBuffer);
		printf("addShellCodeIntoSection Failed!---Section:%d 没有足够的空间存放shellCode\n",sectionNum);
	}


	PBYTE pcodeBegin=NULL;
	pcodeBegin=getCodeBeginFromImageBuffer(pImageBuffer,pSectionHeader);
	

	//将shellCode复制到ImageBuffer对应section中
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


//判断Section是否足够存储shellCode的代码
//pSectionHeader:要放入代码的section的Header
//shellCodeLength:代码区长度
//返回值:成功则返回1，失败则返回0
DWORD checkSectionHeaderCouldWriteCode(IN PIMAGE_SECTION_HEADER pSectionHeader,DWORD shellCodeLength){
	if((pSectionHeader->SizeOfRawData<pSectionHeader->Misc.VirtualSize) || ((pSectionHeader->SizeOfRawData-pSectionHeader->Misc.VirtualSize)<shellCodeLength)){
		return 0;
	}
	return 1;
}



//从ImageBuffer中获得能够注入代码的位置
//返回注入的代码在ImageBuffer中的位置了
PBYTE getCodeBeginFromImageBuffer(IN LPVOID pImageBuffer,IN PIMAGE_SECTION_HEADER pSectionHeader){
	PBYTE pcodeBegin=NULL;
	pcodeBegin=(PBYTE)((DWORD)pImageBuffer+pSectionHeader->VirtualAddress+pSectionHeader->Misc.VirtualSize);
	return pcodeBegin;
}

//将ImageBuffer中的地址转换为运行时的地址
//pImageBuffer
//imageBufferRunAddr在ImageBuffer中的地址了
//返回运行时的地址
DWORD changeImageBufferAddressToRunTimeAddress(IN LPVOID pImageBuffer,DWORD imageBufferRunAddr){
	DWORD callAddressTo=0;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader = getOptionHeader(pImageBuffer);
	callAddressTo=((pOptionHeader->ImageBase)+(imageBufferRunAddr-(DWORD)pImageBuffer));
	
	return callAddressTo;
	
}

//将ImageBuffer中的地址转换为E8或E9指令后面跳转的地址的硬编码
//pImageBuffer
//imageBufferRunAddr在ImageBuffer中的地址了
//E8E9RunTimeAddress:E8或E9指令运行时的地址
DWORD changeE8E9AddressFromImageBuffer(IN LPVOID pImageBuffer,DWORD imageBufferRunAddr,DWORD E8E9RunTimeAddress){
	DWORD runTimeAddress=changeImageBufferAddressToRunTimeAddress(pImageBuffer,imageBufferRunAddr);
	DWORD returnAddressTo=changeE8E9AddressFromRunTimeBuffer(E8E9RunTimeAddress,runTimeAddress);
	return returnAddressTo;
	
}

//将RunTImeBuffer中的地址转换为E8或E9指令后面跳转的地址的硬编码
//E8E9RunTimeAddress:E8或E9指令运行时的地址
//rumTimeAddress:要转换的运行时地址
//返回：转换后的硬编码地址
DWORD changeE8E9AddressFromRunTimeBuffer(DWORD E8E9RunTimeAddress,DWORD rumTimeAddress){
	DWORD returnAddress=0;
	returnAddress=rumTimeAddress-(E8E9RunTimeAddress+5);
	return returnAddress;
	
}

//获得程序运行时入口的地址
//pBuffer
//返回入口地址
PBYTE getEntryRunTimeAddress(LPVOID pBuffer){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader= getOptionHeader(pBuffer);

	return (PBYTE)(pOptionHeader->ImageBase+pOptionHeader->AddressOfEntryPoint);

}

//修改程序运行时入口地址
//pImageBuffer
//imageBufferRunAddress在ImageBuffer中的地址了
void changeEntryPosByImageBufferAddress(LPVOID pImageBuffer,DWORD imageBufferRunAddress){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader= getOptionHeader(pImageBuffer);
	pOptionHeader->AddressOfEntryPoint=imageBufferRunAddress-(DWORD)pImageBuffer;
}

//修改section的权限
//pBuffer
//sectionNum Section的地址
//characteristics：具体的权限，如0x60000020
//成功，返回1，失败，返回0
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

//在pBuffer中将PE的NT头和Section表头提升到Dos头下
//pBuffer
//返回值:Dos头下的间隙的大小，0:Dos头下没有间隙
DWORD topPENTAndSectionHeader(IN LPVOID pBuffer){
	DWORD copySize=0;
	PIMAGE_DOS_HEADER dosHeader = getDosHeader(pBuffer);
	PIMAGE_NT_HEADERS ntHeader = getNTHeader(pBuffer);
	PIMAGE_FILE_HEADER fileHeader = getPEHeader(pBuffer);
	WORD sectionNum=getSectionNum(pBuffer);
	//Dos废数据字段的开头
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
	
	//获得第一个节表头
	PIMAGE_SECTION_HEADER pSectionHeader1 = getSection(pBuffer,1);

	//提升NT头，并将原NT头剩余的部分置0
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

//获得节表的最后一个字节的下一个字节的地址
//pBuffer
//返回值:LPVOID,还是一个节表指针，用于新增节表
LPVOID getSectionEnderNext(IN LPVOID pBuffer){

	WORD sectionNum=getSectionNum(pBuffer);
	//获得第一个节表头
	PIMAGE_SECTION_HEADER pSectionHeader1 = getSection(pBuffer,1);

	LPVOID pSectionEnderNext=(LPVOID)(pSectionHeader1+sectionNum);

	return pSectionEnderNext;



}

//判断是否可以添加一个节表,若最后一个节表有80个字节全为0,则可以添加
//pBuffer
//返回值:1成功,0失败
DWORD checkCanAddSection(IN LPVOID pBuffer){


	char* fillZeroStart=(char*)getSectionEnderNext(pBuffer);

	int i=0;
	int checkLen=2*sizeof(IMAGE_SECTION_HEADER);
	for(i=0;i<checkLen;i++){
		if(*(fillZeroStart+i))return 0;
	}

	return 1;

}

//新增一个节
//pImageBuffer
//sizeOfNewSection,新增的字节数
//pNewBuffer返回成功后newBuffer地址
//characteristics：具体的权限，如0x60000020
//返回值 1成功 0失败
DWORD addNewSection(IN LPVOID pImageBuffer,DWORD sizeOfNewSection,DWORD characteristics,OUT LPVOID* pNewImageBuffer){
	//获得optionHeader中所需要的数据
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pImageBuffer);
	DWORD sizeOfImage=pOptionHeader->SizeOfImage;
	DWORD sectionAlignment=pOptionHeader->SectionAlignment;

	//修改sizeOfNewSection
	sizeOfNewSection=changeNumberByBase(sectionAlignment,sizeOfNewSection);

	DWORD newBufferSize=sizeOfImage+sizeOfNewSection;

	//申请内存用于存储新的pBuffer
	LPVOID pNewImageBufferTmp=NULL;
	pNewImageBufferTmp=malloc(newBufferSize);

	if(!pNewImageBufferTmp)	
	{	

		printf("addNewSection Failed---malloc pNewImageBufferTmp失败!\n ");
		
		return 0;
	}
	
	memset(pNewImageBufferTmp,0,newBufferSize);
	
	//将pBuffer的数据读入到pNewBufferTmp
	memcpy(pNewImageBufferTmp,pImageBuffer,sizeOfImage);
	


	
	PIMAGE_FILE_HEADER fileHeader = getPEHeader(pNewImageBufferTmp);

	//原来section的数量
	WORD sectionNumBefore=fileHeader->NumberOfSections;
	

	//修改sizeOfImage
	pOptionHeader=getOptionHeader(pNewImageBufferTmp);
	pOptionHeader->SizeOfImage=newBufferSize;
	

	//获得新增节表头
	PIMAGE_SECTION_HEADER pNewSectionHeader=(PIMAGE_SECTION_HEADER)getSectionEnderNext(pNewImageBufferTmp);
	
	//Copy最后一个节表
	PIMAGE_SECTION_HEADER pLastSectionHeader=getSection(pNewImageBufferTmp,sectionNumBefore);
	*pNewSectionHeader=*(pLastSectionHeader);
	
	(fileHeader->NumberOfSections)++;

	//修改新增节表名字
	BYTE names[8]={'.','A','D','D',0};
	BYTE* pName=pNewSectionHeader->Name;
	memcpy(pName,names,8);
	
	//修改新增节表属性
	pNewSectionHeader->PointerToRawData=pLastSectionHeader->PointerToRawData+pLastSectionHeader->SizeOfRawData;
	pNewSectionHeader->SizeOfRawData=sizeOfNewSection;
	pNewSectionHeader->VirtualAddress=sizeOfImage;
	pNewSectionHeader->Characteristics=characteristics;
	pNewSectionHeader->Misc.VirtualSize=sizeOfNewSection-sectionAlignment+1;

	*pNewImageBuffer=pNewImageBufferTmp;
	

	
	return 1;
}


//获得FileBuffer的大小
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

//直接在FileBuffer中新增一个节
//pFileBuffer
//sizeOfNewSection,新增的字节数
//pNewFileBuffer返回成功后newFileBuffer地址
//characteristics：具体的权限，如0x60000020
//返回值 返回新增节首地址的RVA 0失败
DWORD addNewSectionByFileBuffer(IN LPVOID pFileBuffer,DWORD sizeOfNewSection,DWORD characteristics,OUT LPVOID* pNewFileBuffer){
	//获得optionHeader中所需要的数据
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);

	DWORD sizeOfHeaders=pOptionHeader->SizeOfHeaders;
	DWORD sizeOfImage=pOptionHeader->SizeOfImage;
	DWORD sectionAlignment=pOptionHeader->SectionAlignment;
	DWORD fileAlignment=pOptionHeader->FileAlignment;

	
	DWORD sizeOfFileBuffer=getFileBufferSize(pFileBuffer);

	//新增节加在FileBuffer中的新增大小
	DWORD newSizeOfFileSection=changeNumberByBase(fileAlignment,sizeOfNewSection);

	//新增节加在ImageBuffer中的新增大小
	DWORD newSizeOfSectionImage=changeNumberByBase(sectionAlignment,sizeOfNewSection);

	//新的sizeOfImage
	DWORD newSizeOfImage=sizeOfImage+newSizeOfSectionImage;
	


	//新的FileBuffer的大小
	DWORD newSizeOfBuffer=sizeOfFileBuffer+newSizeOfFileSection;

	

	//申请内存用于存储新的pBuffer
	LPVOID pNewFileBufferTmp=NULL;
	pNewFileBufferTmp=malloc(newSizeOfBuffer);

	if(!pNewFileBufferTmp)	
	{	

		printf("addNewSectionByFileBuffer Failed---malloc pNewFileBufferTmp失败!\n ");
		
		return 0;
	}
	
	memset(pNewFileBufferTmp,0,newSizeOfBuffer);
	
	//将pBuffer的数据读入到pNewBufferTmp
	memcpy(pNewFileBufferTmp,pFileBuffer,sizeOfFileBuffer);
	
	PIMAGE_FILE_HEADER fileHeader = getPEHeader(pNewFileBufferTmp);
	
	WORD sectionNumBefore=fileHeader->NumberOfSections;

	//修改sizeOfImage
	pOptionHeader=getOptionHeader(pNewFileBufferTmp);
	pOptionHeader->SizeOfImage=newSizeOfImage;
	
	

	//获得新增节表头
	PIMAGE_SECTION_HEADER pNewSectionHeader=(PIMAGE_SECTION_HEADER)getSectionEnderNext(pNewFileBufferTmp);
	
	//Copy最后一个节表
	PIMAGE_SECTION_HEADER pLastSectionHeader=getSection(pNewFileBufferTmp,sectionNumBefore);
	*pNewSectionHeader=*(pLastSectionHeader);
	
	
	(fileHeader->NumberOfSections)++;

	//修改新增节表名字
	BYTE names[8]={'.','A','D','D',0};
	BYTE* pName=pNewSectionHeader->Name;
	memcpy(pName,names,8);
	
	//修改新增节表属性
	pNewSectionHeader->PointerToRawData=pLastSectionHeader->PointerToRawData+pLastSectionHeader->SizeOfRawData;
	pNewSectionHeader->SizeOfRawData=newSizeOfFileSection;
	pNewSectionHeader->VirtualAddress=sizeOfImage;
	pNewSectionHeader->Characteristics=characteristics;
	pNewSectionHeader->Misc.VirtualSize=newSizeOfSectionImage-sectionAlignment+1;

	*pNewFileBuffer=pNewFileBufferTmp;
	

	
	return pNewSectionHeader->PointerToRawData;
}


//扩展最后一个节表
//pBuffer
//addSize,增加的字节数
//pNewBuffer返回成功后newBuffer地址
//characteristics：具体的权限，如0x60000020
//返回值 1成功 0失败
DWORD extendTheLastSection(IN LPVOID pImageBuffer,DWORD addSizeNew,DWORD characteristics,OUT LPVOID* pNewImageBuffer){
	//获得optionHeader中所需要的数据
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pImageBuffer);
	DWORD sizeOfImage=pOptionHeader->SizeOfImage;
	DWORD sectionAlignment=pOptionHeader->SectionAlignment;

	//获得FileHeader中所需要的数据
	PIMAGE_FILE_HEADER fileHeader = getPEHeader(pImageBuffer);
	WORD sectionNum=fileHeader->NumberOfSections;

	
	
	//修改addSize
	DWORD sizeOfNewSection=changeNumberByBase(sectionAlignment,addSizeNew);


	DWORD newBufferSize=sizeOfImage+sizeOfNewSection;

	//申请内存用于存储新的pBuffer
	LPVOID pNewImageBufferTmp=NULL;
	pNewImageBufferTmp=malloc(newBufferSize);

	if(!pNewImageBufferTmp)	
	{	

		printf("extendTheLastSection---malloc pNewImageBufferTmp失败!\n ");
		
		return 0;
	}
	
	memset(pNewImageBufferTmp,0,newBufferSize);
	
	

	//将pBuffer的数据读入到pNewBufferTmp
	memcpy(pNewImageBufferTmp,pImageBuffer,sizeOfImage);

	//修改pNewImageBufferTmp的SizeOfImage
	pOptionHeader=getOptionHeader(pNewImageBufferTmp);
	pOptionHeader->SizeOfImage=newBufferSize;
	
	//获得pNewImageBufferTmp最后一个节表
	PIMAGE_SECTION_HEADER pLastSectionHeader=getSection(pNewImageBufferTmp,sectionNum);
	

	//修改sizeOfImage
	pOptionHeader=getOptionHeader(pNewImageBufferTmp);
	pOptionHeader->SizeOfImage=newBufferSize;
	
	
	//修改最后一个节表名字
	BYTE names[8]={'.','E','X','T','E','N','D',0};
	BYTE* pName=pLastSectionHeader->Name;
	memcpy(pName,names,8);
	
	//修改最后一个节表属性
	pLastSectionHeader->SizeOfRawData+=sizeOfNewSection;
	pLastSectionHeader->Characteristics=characteristics;
	

	pLastSectionHeader->Misc.VirtualSize=pLastSectionHeader->SizeOfRawData-sectionAlignment+1;
	*pNewImageBuffer=pNewImageBufferTmp;
	

	
	return 1;
}

//合并所有节
//pBuffer
//characteristics 合并后只有一个节，要运行，可设置权限为0xE0000020，若还要增加其他节，可设置其他权限，但无法运行
//pNewBuffer返回成功后newBuffer地址
//返回值 1成功 0失败
DWORD mergeAllSections(IN LPVOID pImageBuffer,DWORD characteristics,OUT LPVOID* pNewImageBuffer){
	//获得optionHeader中所需要的数据
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pImageBuffer);
	DWORD sizeOfImage=pOptionHeader->SizeOfImage;
	DWORD sizeOfHeaders=pOptionHeader->SizeOfHeaders;
	DWORD sectionAlignment=pOptionHeader->SectionAlignment;

	//获得FileHeader中所需要的数据
	PIMAGE_FILE_HEADER fileHeader = getPEHeader(pImageBuffer);
	WORD sectionNum=fileHeader->NumberOfSections;
	
	//获得最后一个节表
	PIMAGE_SECTION_HEADER pLastSectionHeader=getSection(pImageBuffer,sectionNum);

	DWORD maxOfSize=0;
	if((pLastSectionHeader->SizeOfRawData) > (pLastSectionHeader->Misc.VirtualSize)){
		maxOfSize=pLastSectionHeader->SizeOfRawData;
	}else{
		maxOfSize=pLastSectionHeader->Misc.VirtualSize;
	}
	maxOfSize=changeNumberByBase(sectionAlignment,pLastSectionHeader->VirtualAddress+maxOfSize-sizeOfHeaders);
	

	//申请内存用于存储新的pBuffer
	LPVOID pNewImageBufferTmp=NULL;
	pNewImageBufferTmp=malloc(maxOfSize+sizeOfHeaders);

	if(!pNewImageBufferTmp)	
	{	

		printf("extendTheLastSection---malloc pNewImageBufferTmp失败!\n ");
		
		return 0;
	}
	
	memset(pNewImageBufferTmp,0,maxOfSize+sizeOfHeaders);
	
	//将pBuffer的数据读入到pNewBufferTmp
	memcpy(pNewImageBufferTmp,pImageBuffer,sizeOfImage);

	//获得第一个节表
	PIMAGE_SECTION_HEADER pFirstSectionHeader=getSection(pNewImageBufferTmp,1);

	

	
	//修改第一个节表名字
	BYTE names[8]={'.','M','E','R','G','E',0};
	BYTE* pName=pFirstSectionHeader->Name;
	memcpy(pName,names,8);
	

	

	//修改第一个节表属性
	pFirstSectionHeader->SizeOfRawData=maxOfSize;
	
	pFirstSectionHeader->Characteristics=characteristics;


	pFirstSectionHeader->Misc.VirtualSize=maxOfSize;


	//将第一个节表后面0x28个字节置零
	if(sectionNum>1){
		memset(pFirstSectionHeader+1,0,sizeof(IMAGE_SECTION_HEADER));
	
	}
	
	//修改sizeOfImage大小
	pOptionHeader=getOptionHeader(pNewImageBufferTmp);
	pOptionHeader->SizeOfImage=maxOfSize+sizeOfHeaders;

	//将section数量修改为1
	fileHeader = getPEHeader(pNewImageBufferTmp);
	fileHeader->NumberOfSections=1;

	*pNewImageBuffer=pNewImageBufferTmp;
	

	
	return 1;
}




//将changeNumber改为baseNumber的整数倍
//baseNum:基数
//changeNumber:需要设置的数
//返回值:改变后的值
DWORD changeNumberByBase(DWORD baseNumber,DWORD changeNumber){
	if(baseNumber<changeNumber){
		DWORD mul=changeNumber/baseNumber;

		return baseNumber*(mul+1);
	}else{
		return baseNumber;
	}


}


//===================PIMAGE_DATA_DIRECTORY=======================


//按index获取DataDirectoryTable信息
//pFileBuffer
//index 序号,序号从1开始,如 1 导出表
//返回 PIMAGE_DATA_DIRECTORY
PIMAGE_DATA_DIRECTORY getDataDirectory(LPVOID pFileBuffer,DWORD index){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	PIMAGE_DATA_DIRECTORY pImageDataDirectory=pOptionHeader->DataDirectory;

	return  pImageDataDirectory+index-1;
	
}

//********************导出表********************************
//通过导出表函数名获得函数地址RVA
//pFileBuffer
//pFunName 函数名字符串指针
//返回值:成功 该函数RVA
DWORD GetFunctionRVAByName(LPVOID pFileBuffer,char* pFunName)
{
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	DWORD imageBase = pOptionHeader->ImageBase;
	

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,1);
	//获得导出表在FileBuffer中的Address位置
	DWORD exportDirectoryFileAddress =(DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pDataDirectory->VirtualAddress);

	//找到导出表
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=(PIMAGE_EXPORT_DIRECTORY)exportDirectoryFileAddress;
	
	DWORD i=0;
	DWORD j=0;

	PDWORD pFileAddressOfFunctions=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfFunctions));
	PDWORD pFileAddressOfNames=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNames));
	PWORD pFileAddressOfNameOrdinals=(PWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNameOrdinals));
	
	//打印函数信息
	for(i=0;i<pExportDirectory->NumberOfNames;i++)
	{
		char* addressOfName=(char*)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,*(pFileAddressOfNames+i)));
		
		//找到函数名
		if(!strcmp(addressOfName,pFunName))
		{
			return (DWORD)(*(pFileAddressOfFunctions+(DWORD)(*(pFileAddressOfNameOrdinals+i))));
			
		}
	}

	printf("GetFunctionAddrByName failed---没有对应函数:%s\n",pFunName);
	return NULL;
}

//通过导出表函数序号获得函数地址RVA,序号来自于.def文件中的定义
//pFileBuffer
//index 序号
//返回值:成功 该函数RVA
DWORD GetFunctionRVAByOrdinals(LPVOID pFileBuffer,DWORD index)
{
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	DWORD imageBase = pOptionHeader->ImageBase;
	

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,1);
	//获得导出表在FileBuffer中的Address位置
	DWORD exportDirectoryFileAddress =(DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pDataDirectory->VirtualAddress);

	//找到导出表
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=(PIMAGE_EXPORT_DIRECTORY)exportDirectoryFileAddress;
	

	PDWORD pFileAddressOfFunctions=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfFunctions));


	index=index-(pExportDirectory->Base);

	if(index<0 || index>pExportDirectory->NumberOfFunctions)
	{
		printf("GetFunctionAddrByOrdinals failed---没有对应编号:%d\n",index);
		return NULL;
	}

	return (DWORD)(*(pFileAddressOfFunctions+index));
		
}


//获取导出表的大小,包括导出表中的函数地址表，函数名称表和函数序号表的大小，以及函数名称表所指向的字符串的大小
//pFileBuffer
//返回值 导出表大小
DWORD getExportDirectorySize(LPVOID pFileBuffer){
	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,1);
	//获得导出表在FileBuffer中的Address位置
	DWORD exportDirectoryFileAddress =RvaToFileBufferAddress(pFileBuffer,pDataDirectory->VirtualAddress);
	//找到导出表
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=(PIMAGE_EXPORT_DIRECTORY)exportDirectoryFileAddress;

	DWORD totalSize=0;

	//IMAGE_EXPORT_DIRECTORY的大小
	DWORD sizeOfExportDirectory=sizeof(IMAGE_EXPORT_DIRECTORY);

	//AddressOfFunctions表大小
	DWORD sizeOfAddressOfFunctions=(pExportDirectory->NumberOfFunctions)*4;

	//AddressOfNameOrdinals表大小
	DWORD sizeOfAddressOfNameOrdinals=(pExportDirectory->NumberOfNames)*2;

	//AddressOfNames表大小
	DWORD sizeOfAddressOfNames=(pExportDirectory->NumberOfNames)*4;

	//函数名称表所有函数名称大小的总和
	DWORD sizeOfAddressStr=0;

	PDWORD pFileAddressOfNames=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNames));

	//循环获得所有名称字符串数组大小，包括数组结尾0
	DWORD i=0;

	for(i=0;i<pExportDirectory->NumberOfNames;i++){
		sizeOfAddressStr+=(strlen((char*)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,*(pFileAddressOfNames+i))))+1);
		
	}
	
	totalSize=sizeOfExportDirectory+sizeOfAddressOfFunctions+sizeOfAddressOfNameOrdinals+sizeOfAddressOfNames+sizeOfAddressStr;

	return totalSize;

}


//移动导出表
//pFileBuffer
//fileRVA 导出表被移动到的RVA
void removeExportDirectory(LPVOID pFileBuffer,DWORD fileRVA){
	//新的导出表在FileBuffer中的首地址
	DWORD newExportDirectoryFileBufferAddress=(DWORD)pFileBuffer+fileRVA;

	//用于复制表格时的指针
	char* newExportDirectoryPointer=(char*)newExportDirectoryFileBufferAddress;

	//寻找导出表
	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,1);
	//获得导出表在FileBuffer中的Address位置
	DWORD exportDirectoryFileAddress =RvaToFileBufferAddress(pFileBuffer,pDataDirectory->VirtualAddress);
	//找到导出表
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=(PIMAGE_EXPORT_DIRECTORY)exportDirectoryFileAddress;

	//复制AddressOfFunctions
	PDWORD pFileAddressOfFunctions=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfFunctions));

	memcpy(newExportDirectoryPointer,pFileAddressOfFunctions,(pExportDirectory->NumberOfFunctions)*4);
	
	//记录newAddressOfFunctions
	PDWORD newAddressOfFunctions=(PDWORD)newExportDirectoryPointer;

	newExportDirectoryPointer+=(pExportDirectory->NumberOfFunctions)*4;
	
	//复制AddressOfNames
	PDWORD pFileAddressOfNames=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNames));

	memcpy(newExportDirectoryPointer,pFileAddressOfFunctions,(pExportDirectory->NumberOfNames)*4);

    //记录newFileAddressOfNames
	PDWORD newFileAddressOfNames=(PDWORD)newExportDirectoryPointer;

	newExportDirectoryPointer+=(pExportDirectory->NumberOfNames)*4;

	//复制AddressOfNameOrdinals
	PWORD pFileAddressOfNameOrdinals=(PWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNameOrdinals));
	
	memcpy(newExportDirectoryPointer,pFileAddressOfNameOrdinals,(pExportDirectory->NumberOfNames)*2);

	//记录newFileAddressOfNameOrdinals
	PDWORD newFileAddressOfNameOrdinals=(PDWORD)newExportDirectoryPointer;

	newExportDirectoryPointer+=(pExportDirectory->NumberOfNames)*2;

	//复制所有的函数名
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

	//复制IMAGE_EXPORT_DIRECTORY结构

	//记录newExportDirectoryAddr
	PIMAGE_EXPORT_DIRECTORY newExportDirectoryAddr=(PIMAGE_EXPORT_DIRECTORY)newExportDirectoryPointer;

	*(newExportDirectoryAddr)=*(pExportDirectory);

	//修改newExportDirectory中的地址了
	newExportDirectoryAddr->AddressOfFunctions=(DWORD)FileBufferAddressToRva(pFileBuffer,(DWORD)newAddressOfFunctions);
	newExportDirectoryAddr->AddressOfNameOrdinals=(DWORD)FileBufferAddressToRva(pFileBuffer,(DWORD)newFileAddressOfNameOrdinals);
	newExportDirectoryAddr->AddressOfNames=(DWORD)FileBufferAddressToRva(pFileBuffer,(DWORD)newFileAddressOfNames);

	//修改目录项
	pDataDirectory->VirtualAddress=(DWORD)FileBufferAddressToRva(pFileBuffer,(DWORD)newExportDirectoryAddr);


	return;

}