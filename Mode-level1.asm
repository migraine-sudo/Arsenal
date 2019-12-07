
/*
Author:Migrane
IF-MODE:Y
Language:asm
Func:LoadLibray
Data:2019-12-7
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

		;Get LoadLibrary
		xor ecx,ecx
		push ebx ;Kernel32
		push edx ;GerProcAddress
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
		push ecx
		mov cx, 0x6c6c  ; ll
		push ecx
		push 0x642e3233 ; 32.d
		push 0x72657375 ; user
		push esp        ; "user32.dll"
		call eax        ; LoadLibrary("user32.dll")

		;MessageBoxA address
		add esp,0x10 ;pop "user32.dll"
		mov edx,[esp+0x4] ;GetProcAddress
		xor ecx,ecx
		push  0x41786F ;oxA
		push 0x42656761;ageB
		push 0x7373654D;Mess
		push esp ;"MessageBoxA"
		push eax;user32.dll
		call edx;GetProcAddress("MessageBoxA")

		;MessageBox
		mov ecx,0x1111767f
		sub ecx,0x11111111
		push ecx
		//push 0x0000656e;ne
		push 0x69617267;grai
		push 0x694d2079;y Mi
		push 0x62206465;ed b
		push 0x6b636168;hack
		push 0x20657261;Are
		push 0x20756F59;You
		mov ebx,esp

/*使用xor来替换/x00*/
		xor ecx,ecx
		push ecx
		//push 0x0
		push 0x656e6961;aine
		push 0x7267694d;Migr
		mov edx,esp

		//int MessageBox( HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption,UINT uType );
		xor ecx,ecx
		push ecx//uTyoe->0
		push edx//lpCaption->Migraine
		push ebx//lpText->You are hacked by Migraine
		push ecx//hWnd->0
		call eax

