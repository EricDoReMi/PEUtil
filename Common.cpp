//通用的函数
#include "Common.h"

//从路径获取文件名
//filePath 文件名完整的路径
char* getFileNameFromPath(char* filePath){
	char splitChar='\\';
	char* pFileName=strrchr(filePath,splitChar)+1;
	return pFileName;
}