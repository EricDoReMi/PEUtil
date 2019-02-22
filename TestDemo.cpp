#include "ShowPE.h"

int main(int argc, char* argv[]){
	
	//��ʼ��
	char* pathName="Hello.exe";
	LPVOID pFileBuffer;
	

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
		freePBuffer(pFileBuffer);
	}
	
	return 0;
}