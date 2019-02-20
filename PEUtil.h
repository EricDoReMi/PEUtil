#ifndef __PEUTIL_H__
#define __PEUTIL_H__
#include<memory.h>
#include<Windows.h>
#include<stdio.h>
#include "PEUtil.h"


//��ȡ�ļ���С
int getFileSize(FILE *P_file);

//��ȡ��FileBuffer
//return 0 ʧ�� 1 �ɹ�
int InitFileBuffer(LPSTR lpszFile);

//�ͷ�FillBuffer
void freePFileBuffer();

//����ǲ���PE�ļ�
//return 0 ʧ�� 1 �ɹ�
int checkIsPEFile();

//��ȡDos�ļ�ͷ
PIMAGE_DOS_HEADER getDosHeader();

//���NT�ļ�ͷ
PIMAGE_NT_HEADERS getNTHeader();


//���PE�ļ�ͷ
PIMAGE_FILE_HEADER getPEHeader();


//��ÿ�ѡ��PEͷ
PIMAGE_OPTIONAL_HEADER32 getOptionHeader();

//��ýڱ�ͷ
PIMAGE_SECTION_HEADER getSectionHeader();

#endif
