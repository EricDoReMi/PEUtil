//ͨ�õĺ���
#include "Common.h"

//��·����ȡ�ļ���
//filePath �ļ���������·��
char* getFileNameFromPath(char* filePath){
	char splitChar='\\';
	char* pFileName=strrchr(filePath,splitChar)+1;
	return pFileName;
}