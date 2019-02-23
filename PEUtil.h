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
//��������							
//**************************************************************************							
//ReadPEFile:���ļ���ȡ��������							
//����˵����							
//lpszFile �ļ�·��							
//pFileBuffer ������ָ��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻�ʵ�ʶ�ȡ�Ĵ�С							
//**************************************************************************							
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);

//**************************************************************************							
//CopyFileBufferToImageBuffer:���ļ���FileBuffer���Ƶ�ImageBuffer							
//����˵����							
//pFileBuffer  FileBufferָ��							
//pImageBuffer ImageBufferָ��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С							
//**************************************************************************
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);
//**************************************************************************							
//CopyImageBufferToNewBuffer:��ImageBuffer�е����ݸ��Ƶ��µĻ�����							
//����˵����							
//pImageBuffer ImageBufferָ��							
//pNewBuffer NewBufferָ��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С							
//**************************************************************************							
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);
//**************************************************************************							
//MemeryTOFile:���ڴ��е����ݸ��Ƶ��ļ�							
//����˵����							
//pMemBuffer �ڴ������ݵ�ָ��							
//size Ҫ���ƵĴ�С							
//lpszFile Ҫ�洢���ļ�·��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С							
//**************************************************************************							
DWORD MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);
//**************************************************************************							
//RvaToFileOffset:���ڴ�ƫ��ת��Ϊ�ļ�ƫ��							
//����˵����							
//pFileBuffer FileBufferָ��							
//dwRva RVA��ֵ							
//����ֵ˵����							
//����ת�����FOA��ֵ  ���ʧ�ܷ���0							
//**************************************************************************							
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);

//�ͷ�Buffer
void freePBuffer(LPVOID pBuffer);

//����ǲ���PE�ļ�
//return 0 ʧ�� 1 �ɹ�
int checkIsPEFile(LPVOID pBuffer);

//��ȡDos�ļ�ͷ
PIMAGE_DOS_HEADER getDosHeader(LPVOID pBuffer);

//���NT�ļ�ͷ
PIMAGE_NT_HEADERS getNTHeader(LPVOID pBuffer);


//���PE�ļ�ͷ
PIMAGE_FILE_HEADER getPEHeader(LPVOID pBuffer);


//��ÿ�ѡ��PEͷ
PIMAGE_OPTIONAL_HEADER32 getOptionHeader(LPVOID pBuffer);

//��ýڱ�ͷ
PIMAGE_SECTION_HEADER getSectionHeader(LPVOID pBuffer);

//��ýڵ�����
WORD getSectionNum(LPVOID pBuffer);

//��ȡ�ڱ���
//index �ڼ����ڱ�
PIMAGE_SECTION_HEADER getSection(LPVOID pBuffer,WORD index);

#endif
