#include "ShowPE.h"

int main(int argc, char* argv[]){
	
	//��ʼ��
	if(InitFileBuffer("Hello.exe") && checkIsPEFile()){
		
		//��ӡDosHeader
		PrintDosHeaders();

		//��ӡNTHeader
		PrintNTHeaders();

		//��ӡPEheader
		PrintPEHeaders();

		//��ӡ��ѡ��PEͷ
		PrintOptionHeaders();
		
		//��ӡ�ڱ���Ϣ
		PrintSectionHeaders();
		freePFileBuffer();
	}
	
	return 0;
}