#pragma once
#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include <windows.h>
//��������Ŀ¼���ļ�ͷ��ƫ��
DWORD RvaToOffset(DWORD dwRva, char * buffer);
//���������ĺ���
void ImportTable(char * buffer);
//����������ĺ���
void ExportTable(char * buffer);
//�����ض�λ��ĺ���
void RelocTable(char * buffer);
//����TLS��ĺ���
void TlsTable(char * buffer);
//�����ӳٵ����ĺ���
void DelayImportTable(char * buffer);

