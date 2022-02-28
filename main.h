#pragma once
#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include <windows.h>
//计算数据目录表到文件头的偏移
DWORD RvaToOffset(DWORD dwRva, char * buffer);
//解析导入表的函数
void ImportTable(char * buffer);
//解析导出表的函数
void ExportTable(char * buffer);
//解析重定位表的函数
void RelocTable(char * buffer);
//解析TLS表的函数
void TlsTable(char * buffer);
//解析延迟导入表的函数
void DelayImportTable(char * buffer);

