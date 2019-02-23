#include "ShowPE.h"

int main(int argc, char* argv[]){
	
	//��ʼ��
	char* pathName="PETool.exe";
	char* pathNameDes="Hello2.exe";
	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;

	if(ReadPEFile(pathName,&pFileBuffer) && checkIsPEFile(pFileBuffer)){
		
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

		DWORD copySize=0;
		copySize= CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
		if(copySize){
			freePBuffer(pFileBuffer);
			copySize=CopyImageBufferToNewBuffer(pImageBuffer,&pNewFileBuffer);
			if(copySize){
				freePBuffer(pImageBuffer);
				copySize=MemeryTOFile(pNewFileBuffer,copySize,pathNameDes);

				if(copySize){
					freePBuffer(pNewFileBuffer);	
				}else{
					printf("MemeryTOFile Failed!");
				}
			}else{
				printf("CopyImageBufferToNewBuffer Failed!");
			}
		}else{
			printf("CopyFileBufferToImageBuffer Failed!");
		}
		
		
		
	}
	
	return 0;
}