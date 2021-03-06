//读取所有的PE头信息
#include "ShowPE.h"

//打印DosHeader
VOID PrintDosHeaders(LPVOID pFileBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pFileBuffer);

	//打印DOC头	
	printf("********************DOC头********************\n");	
	printf("e_magic(MZ标志):%x\n",pDosHeader->e_magic);	
	printf("e_lfanew(PE偏移):%x\n",pDosHeader->e_lfanew);
}

//打印NTHeader
VOID PrintNTHeaders(LPVOID pFileBuffer){
	PIMAGE_NT_HEADERS pNTHeader = NULL;	
	pNTHeader=getNTHeader(pFileBuffer);
	printf("********************NT头********************\n");	
	printf("Signature(PE标志):%x\n",pNTHeader->Signature);
}

//打印PEheader
VOID PrintPEHeaders(LPVOID pFileBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader=getPEHeader(pFileBuffer);
	printf("********************PE头********************\n");	
	printf("Machine(运行的平台):%x\n",pPEHeader->Machine);	
	printf("NumberOfSections(节的数量了):%x\n",pPEHeader->NumberOfSections);	
	printf("SizeOfOptionalHeader(可选PE头的大小了):%x\n",pPEHeader->SizeOfOptionalHeader);
}

//打印可选的PE头
VOID PrintOptionHeaders(LPVOID pFileBuffer){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	printf("********************OPTIOIN_PE头********************\n");
	printf("OPTION_PE:%x\n",pOptionHeader->Magic);	
	printf("SizeOfCode:%x\n",pOptionHeader->SizeOfCode);	
	printf("SizeOfInitializedData:%x\n",pOptionHeader->SizeOfInitializedData);	
	printf("SizeOfUninitializedData:%x\n",pOptionHeader->SizeOfUninitializedData);	
	printf("AddressOfEntryPoint:%x\n",pOptionHeader->AddressOfEntryPoint);	
	printf("BaseOfCode:%x\n",pOptionHeader->BaseOfCode);	
	printf("BaseOfData:%x\n",pOptionHeader->BaseOfData);	
	printf("ImageBase:%x\n",pOptionHeader->ImageBase);	
	printf("SectionAlignment:%x\n",pOptionHeader->SectionAlignment);	
	printf("SizeOfImage:%x\n",pOptionHeader->SizeOfImage);	
	printf("CheckSum:%x\n",pOptionHeader->CheckSum);	
}

//打印节表信息
VOID PrintSectionHeaders(LPVOID pFileBuffer){
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	

	
	pSectionHeader=getSectionHeader(pFileBuffer);
	
	WORD sectionNum=getSectionNum(pFileBuffer);


	printf("********************SECTION头********************\n");
	WORD i=0;
	for(i=0;i<sectionNum;i++){
		BYTE names[9]={0};
		BYTE* p_name=names;
		p_name=pSectionHeader->Name;
		printf("-----SectionNum:%d-----\n",i+1);
		printf("SectionName:%s\n",p_name);
		printf("Misc:%X\n",pSectionHeader->Misc);
		printf("SizeOfRawData:%X\n",pSectionHeader->SizeOfRawData);
		printf("PointerToRawData:%X\n",pSectionHeader->PointerToRawData);
		printf("PointerToRelocations:%X\n",pSectionHeader->PointerToRelocations);
		printf("PointerToLinenumbers:%X\n",pSectionHeader->PointerToLinenumbers);
		printf("NumberOfRelocations:%X\n",pSectionHeader->NumberOfRelocations);
		printf("NumberOfLinenumbers:%X\n",pSectionHeader->NumberOfLinenumbers);
		printf("Characteristics:%X\n",pSectionHeader->Characteristics);
		pSectionHeader=(PIMAGE_SECTION_HEADER)((char*)pSectionHeader+40);

	}


}



//打印目录表
VOID PrintDataDirectory(LPVOID pFileBuffer){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	
	PIMAGE_DATA_DIRECTORY pImageDataDirectory=pOptionHeader->DataDirectory;

	//导出表、导入表、资源表、异常信息表、安全证书表、重定位表、调试信息表、版权所有表、全局指针表
    //TLS表、加载配置表、绑定导入表、IAT表、延迟导入表、COM信息表 最后一个保留未使用。
	char* pTableNames[16]={"导出表","导入表","资源表","异常信息表","安全证书表","重定位表","调试信息表","版权所有表","全局指针表","TLS表","加载配置表","绑定导入表","IAT表","延迟导入表","COM信息表","保留表"};

	printf("===============PrintDataDirectory=============\n");
	PIMAGE_DATA_DIRECTORY pDataDirectory=NULL;

	DWORD i=0;
	for(i=0;i<16;i++){
		pDataDirectory=pImageDataDirectory+i;
		printf("===============%s=============\n",pTableNames[i]);
		printf("地址:%X\n",pDataDirectory->VirtualAddress);
		printf("表大小:%X\n",pDataDirectory->Size);

	}
}

//打印导出表
VOID PrintExportTable(LPVOID pFileBuffer){

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,1);
	//获得导出表在FileBuffer中的Address位置
	DWORD exportDirectoryFileAddress =(DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pDataDirectory->VirtualAddress);

	//找到导出表
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=(PIMAGE_EXPORT_DIRECTORY)exportDirectoryFileAddress;

	printf("=============导出表信息=================\n");
	printf("Name:%s\n",(DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->Name));
	printf("Base:%d\n",pExportDirectory->Base);
	printf("NumberOfFunctions:%d\n",pExportDirectory->NumberOfFunctions);
	printf("NumberOfNames:%d\n",pExportDirectory->NumberOfNames);
	printf("AddressOfFunctions:%X\n",pExportDirectory->AddressOfFunctions);
	printf("AddressOfNames:%X\n",pExportDirectory->AddressOfNames);
	printf("AddressOfNameOrdinals:%X\n",pExportDirectory->AddressOfNameOrdinals);
	printf("******导出表函数******\n");
	

	DWORD i=0;
	DWORD j=0;

	PDWORD pFileAddressOfFunctions=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfFunctions));
	PDWORD pFileAddressOfNames=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNames));
	PWORD pFileAddressOfNameOrdinals=(PWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNameOrdinals));
	
	//打印函数信息
	for(i=0;i<pExportDirectory->NumberOfFunctions;i++){
		DWORD addressOfFunction=*(pFileAddressOfFunctions+i);
		
		if(addressOfFunction){

			printf("AddressOfFunction:%X\t",addressOfFunction);
			printf("Ordinal:%d\t",i+pExportDirectory->Base);
			
			for(j=0;j<pExportDirectory->NumberOfNames;j++){
				if(*(pFileAddressOfNameOrdinals+j)==i){
					printf("AddressOfName:%s\t",(DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,*(pFileAddressOfNames+j)));
				}
			}
			printf("\n");
		}

		
	}

}	


//打印重定位表
VOID PrintRelocationTable(LPVOID pFileBuffer)
{

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,6);
	//获得重定位表在FileBuffer中的Address位置
	DWORD relocationFileBufferAddress =RvaToFileBufferAddress(pFileBuffer,pDataDirectory->VirtualAddress);

	//找到
	PIMAGE_BASE_RELOCATION pRelocationTables=(PIMAGE_BASE_RELOCATION)relocationFileBufferAddress;

	DWORD i=0;

	printf("=============重定位表信息=================\n");
	//pRelocationTables->SizeOfBlock || pRelocationTables->VirtualAddress 全为0时，则遍历结束
	while(pRelocationTables->VirtualAddress)
	{
		i++;
		DWORD sizeOfBlock=pRelocationTables->SizeOfBlock;
		DWORD virtualAddress=pRelocationTables->VirtualAddress;
		DWORD sectionIndex=RvaToSectionIndex(pFileBuffer,virtualAddress);
		
		//打印每个重定位表的具体信息
		printf("***表:%d\tsizeOfBlock:%d\tvirtualAddress:%X\tsectionIndex:%d\n",i,sizeOfBlock,virtualAddress,sectionIndex);
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
			DWORD fileOffSet=RvaToFileOffset(pFileBuffer,rvaChange);
			char* isChangeTxt=NULL;
			isChangeTxt="否";
			if((isChange^0x3000)==0){
				isChangeTxt="是";
			}
			

			printf("%d\tChange:%s\trva:%X\tfileOffSet:%X\n",j+1,isChangeTxt,rvaChange,fileOffSet);
	
			pStartBlock++;

		}
		

		//下一个重定位表地址
		pRelocationTables=(PIMAGE_BASE_RELOCATION)((char*)pRelocationTables+sizeOfBlock);


	}


}

//打印导入表
VOID PrintImportTable(LPVOID pFileBuffer)
{

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,2);
	//获得导入表在FileBuffer中的Address位置
	DWORD importTableFileBufferAddress =RvaToFileBufferAddress(pFileBuffer,pDataDirectory->VirtualAddress);

	//找到第一个导入表
	PIMAGE_IMPORT_DESCRIPTOR pImportTables=(PIMAGE_IMPORT_DESCRIPTOR)importTableFileBufferAddress;


	printf("=============导入表信息=================\n");
	
	while(pImportTables->Characteristics|pImportTables->FirstThunk|pImportTables->ForwarderChain|pImportTables->Name|pImportTables->OriginalFirstThunk|pImportTables->TimeDateStamp)
	{
		
		DWORD nameRVA=pImportTables->Name;
		char* pDllNames=(char*)RvaToFileBufferAddress(pFileBuffer,nameRVA);
		printf("***********%s*********\n",pDllNames);
		DWORD timeDateStamp = pImportTables->TimeDateStamp;
		printf("***timeStamp:%d***\n");
		DWORD originalFirstThunk=pImportTables->OriginalFirstThunk;
		DWORD firstThunk=pImportTables->FirstThunk;

		PDWORD pOriginalFirstThunk=(PDWORD)RvaToFileBufferAddress(pFileBuffer,originalFirstThunk);

		PDWORD pFirstThunk=(PDWORD)RvaToFileBufferAddress(pFileBuffer,firstThunk);

		//遍历OriginalFirstThunk
		printf("------------OriginalFirstThunk----------\n");
		while(*pOriginalFirstThunk){
			DWORD imageData=(DWORD)*pOriginalFirstThunk;
			//最高位判断最高位是否为1 如果是,那么除去最高位的值就是函数的导出序号				

			if(imageData & 0x80000000){
				DWORD indexOfExport=imageData & 0x7FFFFFFF;//导出表的函数序号
				printf("导出表函数序号:%d\n",indexOfExport);

			}else{
				PIMAGE_IMPORT_BY_NAME pImportByName=(PIMAGE_IMPORT_BY_NAME)RvaToFileBufferAddress(pFileBuffer,imageData);//导出表函数名
				char* pImportFunNames=(char*)pImportByName->Name;
				printf("导出表函数名称:%s\n",pImportFunNames);
			}
			pOriginalFirstThunk++;
		}

		//遍历FirstThunk
		printf("------------FirstThunk----------\n");
		while(*pFirstThunk){
			DWORD imageData=(DWORD)*pFirstThunk;
			//最高位判断最高位是否为1 如果是,那么除去最高位的值就是函数的导出序号				

			if(imageData & 0x80000000){
				DWORD indexOfExport=imageData & 0x7FFFFFFF;//导出表的函数序号
				printf("导出表序号:%d\n",indexOfExport);

			}else{
				PIMAGE_IMPORT_BY_NAME pImportByName=(PIMAGE_IMPORT_BY_NAME)RvaToFileBufferAddress(pFileBuffer,imageData);//导出表函数名
				char* pImportFunNames=(char*)pImportByName->Name;
				printf("导出表函数名称:%s\n",pImportFunNames);
			}
			pFirstThunk++;
		}
	

		//下一个导入表地址
		pImportTables++;


	}


}

//打印绑定导入表
VOID PrintBoundImportTable(LPVOID pFileBuffer)
{

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,12);

	//获得导入表在FileBuffer中的Address位置
	DWORD importBoundTableFileBufferAddress =RvaToFileBufferAddress(pFileBuffer,pDataDirectory->VirtualAddress);

	//找到第一个绑定导入表
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pImportBoundTable=(PIMAGE_BOUND_IMPORT_DESCRIPTOR)importBoundTableFileBufferAddress;
	
	//绑定导入表的表头
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pImportBoundTable1=pImportBoundTable;

	printf("=============绑定导入表信息=================\n");
	DWORD i=0;

	while(pImportBoundTable->NumberOfModuleForwarderRefs|pImportBoundTable->OffsetModuleName|pImportBoundTable->TimeDateStamp)
	{
		DWORD timeDateStamp=pImportBoundTable->TimeDateStamp;
		WORD  numberOfModuleForwarderRefs=0;

		numberOfModuleForwarderRefs=pImportBoundTable->NumberOfModuleForwarderRefs;
		
		printf("---IMAGE_BOUND_IMPORT_DESCRIPTOR---\n");
		printf("numberOfModuleForwarderRefs:%d\n",numberOfModuleForwarderRefs);

		printf("timeDateStamp:%d\n",pImportBoundTable->TimeDateStamp);
		
		printf("OffsetModuleName:%s\n",(char*)pImportBoundTable1+pImportBoundTable->OffsetModuleName);

		DWORD j=0;
		
		PIMAGE_BOUND_FORWARDER_REF pBoundForwarderRef=(PIMAGE_BOUND_FORWARDER_REF)pImportBoundTable+1;

		
		printf("***********IMAGE_BOUND_FORWARDER_REF***************\n");

		for(j=0;j<numberOfModuleForwarderRefs;j++){
			
			printf("timeDateStamp:%d\n",pBoundForwarderRef->TimeDateStamp);
			printf("OffsetModuleName:%s\n",(char*)pImportBoundTable1+pBoundForwarderRef->OffsetModuleName);
			printf("Reserved:%d\n",pBoundForwarderRef->Reserved);

			pBoundForwarderRef++;
			
		}
		

		//下一个绑定导入表地址
		pImportBoundTable+=(numberOfModuleForwarderRefs+1);


	}


}

//打印资源表
VOID PrintResourceTable(LPVOID pFileBuffer){
	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,3);

	//获得资源表在FileBuffer中的Address位置
	DWORD resourceTableFileBufferAddress =RvaToFileBufferAddress(pFileBuffer,pDataDirectory->VirtualAddress);
	
	printResource(pFileBuffer,(DWORD)resourceTableFileBufferAddress,(PIMAGE_RESOURCE_DIRECTORY)resourceTableFileBufferAddress,1);
}

//递归打印资源表的函数
//TableAddr:资源表表头的位置
//pResourceDir
//index:层数
VOID printResource(LPVOID pFileBuffer,DWORD TableAddr,PIMAGE_RESOURCE_DIRECTORY pResourceDir,int index){
	
	WORD countOfDirectory=0;
	countOfDirectory=pResourceDir->NumberOfIdEntries+pResourceDir->NumberOfNamedEntries;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceDirEntry=(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir+1);

	WORD i=0;
	


	for(i=0;i<countOfDirectory;i++){

		if(pResourceDirEntry->NameIsString){
			PIMAGE_RESOURCE_DIR_STRING_U pString = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResourceDir + pResourceDirEntry->NameOffset);
			WCHAR nodeString[256]={0};
			wcsncpy(nodeString,pString->NameString,pString->Length);
				
			printIndexTitle(index,nodeString);

				
		}else{
			DWORD id=pResourceDirEntry->NameOffset;
			if(index==1){
				WCHAR nodeString[256]={0};
				switch(id)
				{
					case 1: 
						wcscpy(nodeString,L"Cursor");
						printIndexTitle(index,nodeString); 
						break;
					case 2: 
						wcscpy(nodeString,L"Bitmap");
						printIndexTitle(index,nodeString); 
						break;
					case 3:
						wcscpy(nodeString,L"Icon");
						printIndexTitle(index,nodeString); 
						break;	
					case 4: 
						wcscpy(nodeString,L"Menu");
						printIndexTitle(index,nodeString); 
						break;
					case 5: 
						wcscpy(nodeString,L"Dialog");
						printIndexTitle(index,nodeString); 
						break;
					case 6: 
						wcscpy(nodeString,L"String");
						printIndexTitle(index,nodeString); 
						break;
					case 7:
						wcscpy(nodeString,L"FontDir");
						printIndexTitle(index,nodeString); 
						break;
					case 8:
						wcscpy(nodeString,L"Font");
						printIndexTitle(index,nodeString); 
						break;
					case 9: 
						wcscpy(nodeString,L"Accelerator");
						printIndexTitle(index,nodeString); 
						break;
					case 10: 
						wcscpy(nodeString,L"RCDATA");
						printIndexTitle(index,nodeString); 
						break;
					case 11:
						wcscpy(nodeString,L"MessageTable");
						printIndexTitle(index,nodeString); 
						break;
					case 12: 
						wcscpy(nodeString,L"GroupCursor");
						printIndexTitle(index,nodeString); 
						break;

					case 14: 
						wcscpy(nodeString,L"GroupIcon");
						printIndexTitle(index,nodeString); 
						break;

					case 16: 
						wcscpy(nodeString,L"Version");
						printIndexTitle(index,nodeString); 
						break;

					case 17: 
						wcscpy(nodeString,L"DlgInclude");
						printIndexTitle(index,nodeString); 
						break;

					case 19: 
						wcscpy(nodeString,L"PlugPlay");
						printIndexTitle(index,nodeString); 
						break;

					case 20: 
						wcscpy(nodeString,L"VXD");
						printIndexTitle(index,nodeString); 
						break;

					case 21: 
						wcscpy(nodeString,L"ANICursor");
						printIndexTitle(index,nodeString); 
						break;

					case 22: 
						wcscpy(nodeString,L"ANIIcon");
						printIndexTitle(index,nodeString); 
						break;

					case 23: 
						wcscpy(nodeString,L"HTML");
						printIndexTitle(index,nodeString); 
						break;


					default: 
						printIndexID(index,id); 
						break;
				}
				
			}else{
				printIndexID(index,id);
			}
			
		}

		if(pResourceDirEntry->DataIsDirectory==0){
			
			PIMAGE_DATA_DIRECTORY  pData = (PIMAGE_DATA_DIRECTORY)((DWORD)TableAddr + (DWORD)pResourceDirEntry->OffsetToData);
			
			CHAR infoString[500]={0};
		
			DWORD fileOffset=RvaToFileOffset(pFileBuffer,pData->VirtualAddress);
			sprintf(infoString,"fileOffset:%x,RVA:%x,size:%x",fileOffset,pData->VirtualAddress,pData->Size);
			printIndexTitle(index+1,infoString);
			
			return;
		
		}

			printResource(pFileBuffer,TableAddr,(PIMAGE_RESOURCE_DIRECTORY)((DWORD)TableAddr+(DWORD)pResourceDirEntry->OffsetToDirectory),index+1);
			
			pResourceDirEntry++;
		
	}

}

//打印names
//index 层数
//names
VOID printIndexTitle(int index,WCHAR* names){
	int i=0;
	
	for(i=0;i<index;i++){
		if(i<index-1){
			printf("    ");
		}else{
			printf("|---");
		}
		
	}
	wprintf(L"%s\n",names);
}

//打印names
//index 层数
//names
VOID printIndexTitle(int index,CHAR* names){
	int i=0;
	
	for(i=0;i<index;i++){
		if(i<index-1){
			printf("    ");
		}else{
			printf("|---");
		}
		
	}
	printf("%s\n",names);
}

//打印ID
//index 层数
//id
VOID printIndexID(int index,DWORD id){
	int i=0;
	
	for(i=0;i<index;i++){
		if(i<index-1){
			printf("    ");
		}else{
			printf("|---");
		}
	}
	if(index==3){
		printf("CodePage:%d\n",id);
	}else{
		printf("ID:%d\n",id);
	}

}




