//��ȡ���е�PEͷ��Ϣ
#include "ShowPE.h"

//��ӡDosHeader
VOID PrintDosHeaders(LPVOID pFileBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pFileBuffer);

	//��ӡDOCͷ	
	printf("********************DOCͷ********************\n");	
	printf("e_magic(MZ��־):%x\n",pDosHeader->e_magic);	
	printf("e_lfanew(PEƫ��):%x\n",pDosHeader->e_lfanew);
}

//��ӡNTHeader
VOID PrintNTHeaders(LPVOID pFileBuffer){
	PIMAGE_NT_HEADERS pNTHeader = NULL;	
	pNTHeader=getNTHeader(pFileBuffer);
	printf("********************NTͷ********************\n");	
	printf("Signature(PE��־):%x\n",pNTHeader->Signature);
}

//��ӡPEheader
VOID PrintPEHeaders(LPVOID pFileBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader=getPEHeader(pFileBuffer);
	printf("********************PEͷ********************\n");	
	printf("Machine(���е�ƽ̨):%x\n",pPEHeader->Machine);	
	printf("NumberOfSections(�ڵ�������):%x\n",pPEHeader->NumberOfSections);	
	printf("SizeOfOptionalHeader(��ѡPEͷ�Ĵ�С��):%x\n",pPEHeader->SizeOfOptionalHeader);
}

//��ӡ��ѡ��PEͷ
VOID PrintOptionHeaders(LPVOID pFileBuffer){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	printf("********************OPTIOIN_PEͷ********************\n");
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

//��ӡ�ڱ���Ϣ
VOID PrintSectionHeaders(LPVOID pFileBuffer){
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	

	
	pSectionHeader=getSectionHeader(pFileBuffer);
	
	WORD sectionNum=getSectionNum(pFileBuffer);


	printf("********************SECTIONͷ********************\n");
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



//��ӡĿ¼��
VOID PrintDataDirectory(LPVOID pFileBuffer){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	
	PIMAGE_DATA_DIRECTORY pImageDataDirectory=pOptionHeader->DataDirectory;

	//�������������Դ���쳣��Ϣ����ȫ֤����ض�λ��������Ϣ����Ȩ���б�ȫ��ָ���
    //TLS���������ñ��󶨵����IAT���ӳٵ����COM��Ϣ�� ���һ������δʹ�á�
	char* pTableNames[16]={"������","�����","��Դ��","�쳣��Ϣ��","��ȫ֤���","�ض�λ��","������Ϣ��","��Ȩ���б�","ȫ��ָ���","TLS��","�������ñ�","�󶨵����","IAT��","�ӳٵ����","COM��Ϣ��","������"};

	printf("===============PrintDataDirectory=============\n");
	PIMAGE_DATA_DIRECTORY pDataDirectory=NULL;

	DWORD i=0;
	for(i=0;i<16;i++){
		pDataDirectory=pImageDataDirectory+i;
		printf("===============%s=============\n",pTableNames[i]);
		printf("��ַ:%X\n",pDataDirectory->VirtualAddress);
		printf("���С:%X\n",pDataDirectory->Size);

	}
}

//��ӡ������
VOID PrintExportTable(LPVOID pFileBuffer){

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,1);
	//��õ�������FileBuffer�е�Addressλ��
	DWORD exportDirectoryFileAddress =(DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pDataDirectory->VirtualAddress);

	//�ҵ�������
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=(PIMAGE_EXPORT_DIRECTORY)exportDirectoryFileAddress;

	printf("=============��������Ϣ=================\n");
	printf("Name:%s\n",(DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->Name));
	printf("Base:%d\n",pExportDirectory->Base);
	printf("NumberOfFunctions:%d\n",pExportDirectory->NumberOfFunctions);
	printf("NumberOfNames:%d\n",pExportDirectory->NumberOfNames);
	printf("AddressOfFunctions:%X\n",pExportDirectory->AddressOfFunctions);
	printf("AddressOfNames:%X\n",pExportDirectory->AddressOfNames);
	printf("AddressOfNameOrdinals:%X\n",pExportDirectory->AddressOfNameOrdinals);
	printf("******��������******\n");
	

	DWORD i=0;
	DWORD j=0;

	PDWORD pFileAddressOfFunctions=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfFunctions));
	PDWORD pFileAddressOfNames=(PDWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNames));
	PWORD pFileAddressOfNameOrdinals=(PWORD)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNameOrdinals));
	
	//��ӡ������Ϣ
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


//��ӡ�ض�λ��
VOID PrintRelocationTable(LPVOID pFileBuffer)
{

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,6);
	//����ض�λ����FileBuffer�е�Addressλ��
	DWORD relocationFileBufferAddress =RvaToFileBufferAddress(pFileBuffer,pDataDirectory->VirtualAddress);

	//�ҵ�
	PIMAGE_BASE_RELOCATION pRelocationTables=(PIMAGE_BASE_RELOCATION)relocationFileBufferAddress;

	DWORD i=0;

	printf("=============�ض�λ����Ϣ=================\n");
	//pRelocationTables->SizeOfBlock || pRelocationTables->VirtualAddress ȫΪ0ʱ�����������
	while(pRelocationTables->VirtualAddress)
	{
		i++;
		DWORD sizeOfBlock=pRelocationTables->SizeOfBlock;
		DWORD virtualAddress=pRelocationTables->VirtualAddress;
		DWORD sectionIndex=RvaToSectionIndex(pFileBuffer,virtualAddress);
		
		//��ӡÿ���ض�λ��ľ�����Ϣ
		printf("***��:%d\tsizeOfBlock:%d\tvirtualAddress:%X\tsectionIndex:%d\n",i,sizeOfBlock,virtualAddress,sectionIndex);
		//����BLOCK������
		DWORD numBlock=0;
		numBlock=(sizeOfBlock-8)/2;
		
		DWORD j=0;
		PWORD pStartBlock=(PWORD)pRelocationTables+4;
		for(j=0;j<numBlock;j++)
		{
			//Ӳ����ط��ĵ�ַ
			DWORD rvaChange=(DWORD)((*(PWORD)pStartBlock)&0x0FFF)+virtualAddress;
			DWORD isChange=(*(PWORD)pStartBlock)&0xF000;
			DWORD fileOffSet=RvaToFileOffset(pFileBuffer,rvaChange);
			char* isChangeTxt=NULL;
			isChangeTxt="��";
			if((isChange^0x3000)==0){
				isChangeTxt="��";
			}
			

			printf("%d\tChange:%s\trva:%X\tfileOffSet:%X\n",j+1,isChangeTxt,rvaChange,fileOffSet);
	
			pStartBlock++;

		}
		

		//��һ���ض�λ���ַ
		pRelocationTables=(PIMAGE_BASE_RELOCATION)((char*)pRelocationTables+sizeOfBlock);


	}


}

//��ӡ�����
VOID PrintImportTable(LPVOID pFileBuffer)
{

	PIMAGE_DATA_DIRECTORY pDataDirectory=getDataDirectory(pFileBuffer,2);
	//��õ������FileBuffer�е�Addressλ��
	DWORD importTableFileBufferAddress =RvaToFileBufferAddress(pFileBuffer,pDataDirectory->VirtualAddress);

	//�ҵ���һ�������
	PIMAGE_IMPORT_DESCRIPTOR pImportTables=(PIMAGE_IMPORT_DESCRIPTOR)importTableFileBufferAddress;


	printf("=============�������Ϣ=================\n");
	
	while(pImportTables->Characteristics|pImportTables->FirstThunk|pImportTables->ForwarderChain|pImportTables->Name|pImportTables->OriginalFirstThunk|pImportTables->TimeDateStamp)
	{
		
		DWORD nameRVA=pImportTables->Name;
		char* pDllNames=(char*)RvaToFileBufferAddress(pFileBuffer,nameRVA);
		printf("***********%s*********\n",pDllNames);
		
		DWORD originalFirstThunk=pImportTables->OriginalFirstThunk;
		DWORD firstThunk=pImportTables->FirstThunk;

		PDWORD pOriginalFirstThunk=(PDWORD)RvaToFileBufferAddress(pFileBuffer,originalFirstThunk);

		PDWORD pFirstThunk=(PDWORD)RvaToFileBufferAddress(pFileBuffer,firstThunk);

		//����OriginalFirstThunk
		printf("------------OriginalFirstThunk----------\n");
		while(*pOriginalFirstThunk){
			DWORD imageData=(DWORD)*pOriginalFirstThunk;
			//���λ�ж����λ�Ƿ�Ϊ1 �����,��ô��ȥ���λ��ֵ���Ǻ����ĵ������				

			if(imageData & 0x80000000){
				DWORD indexOfExport=imageData & 0x7FFFFFFF;//������ĺ������
				printf("���������:%d\n",indexOfExport);

			}else{
				PIMAGE_IMPORT_BY_NAME pImportByName=(PIMAGE_IMPORT_BY_NAME)RvaToFileBufferAddress(pFileBuffer,imageData);//����������
				char* pImportFunNames=(char*)pImportByName->Name;
				printf("����������:%s\n",pImportFunNames);
			}
			pOriginalFirstThunk++;
		}

		//����FirstThunk
		printf("------------FirstThunk----------\n");
		while(*pFirstThunk){
			DWORD imageData=(DWORD)*pFirstThunk;
			//���λ�ж����λ�Ƿ�Ϊ1 �����,��ô��ȥ���λ��ֵ���Ǻ����ĵ������				

			if(imageData & 0x80000000){
				DWORD indexOfExport=imageData & 0x7FFFFFFF;//������ĺ������
				printf("���������:%d\n",indexOfExport);

			}else{
				PIMAGE_IMPORT_BY_NAME pImportByName=(PIMAGE_IMPORT_BY_NAME)RvaToFileBufferAddress(pFileBuffer,imageData);//����������
				char* pImportFunNames=(char*)pImportByName->Name;
				printf("����������:%s\n",pImportFunNames);
			}
			pFirstThunk++;
		}

	
		

		//��һ��������ַ
		pImportTables++;


	}


}	



