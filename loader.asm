;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;      in loving memory
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
.386
.model          flat,stdcall

option          casemap:none

include         include\windows.inc
include         include\kernel32.inc
include         include\masm32.inc
include         include\msvcrt.inc

includelib      C:\masm32\lib\kernel32.lib
includelib      C:\masm32\lib\msvcrt.lib

.data 

f_name  db '.\calc.exe',00h
m_delta dd 0
m_entry dd 0

.code 

parse_iat:    ;edx = OptionalHeder    

 push          ebx
 push          ecx
 mov           ebx,dword ptr[edx + 068h] ;ebx = import table
@@:
 mov           ecx,dword ptr[edx + 01ch] ;ImageBase
 add           ecx,ebx;dword ptr[ebx].VirtualAddress
 mov           eax,dword ptr[edx + 01ch] ;ImageBase
 add           eax,dword ptr[ecx + 0ch] ;Name1
 cmp           dword ptr[ecx + 0ch],0 ;Name1,0     
 je            @@break

 push         edx
 push         ecx
 
 push         eax
 call         LoadLibrary
  
 pop          ecx                       ;ecx = IMAGE_IMPORT_DESCRIPTOR
 pop          edx                       ;edx = Optional Header
 
 push         ebx
 
 mov          ebx,dword ptr[edx + 01ch] ;ImageBase
 add          ebx,dword ptr[ecx + 010h] ;FirstThunk
@@i_loop: 
 cmp          dword ptr[ebx],0
 je           @@i_break; 
 
 push         ecx
 push         eax
 push         edx
 
 test         dword ptr[ebx],IMAGE_ORDINAL_FLAG32
 je           @@no_ordinals
 
 mov          ecx,dword ptr[ebx]
 and          ecx,0ffffh
 
 jmp          @@g_proc
 
@@no_ordinals: 
 mov          ecx,dword ptr[edx + 01ch] ;ImageBase
 add          ecx,dword ptr[ebx]
 add          ecx,2 

@@g_proc:
 push         ecx
 push         eax
 call         GetProcAddress
 
 mov          dword ptr[ebx],eax
 
 pop          edx
 pop          eax
 add          ebx,4
 pop          ecx
 jmp          @@i_loop
 
@@i_break: 
 
 pop           ebx
 
 add           ebx,sizeof( IMAGE_IMPORT_DESCRIPTOR )
 jmp           @b
@@break:

 pop           ecx
 pop           ebx
 ret
 
fix_relocations:    ;in delta = addrInMem - Orginal OptionalHeader.ImageBase, pe_hnd *mem = MZ 
 push          ebx
 push          edx
 push          ecx
 mov           ebx,dword ptr[esp + 014h]         ;ebx = ImageBase in mem 
 add           ebx,dword ptr[ebx + 03ch] ;e_lfanew
 mov           edx,dword ptr[esp + 014h]
 add           edx,dword ptr[ebx + 0a0h] ;edx=relloc
 push          esi
 push          edi
__l1:          
 cmp           dword ptr[edx],0         
 jle           __break;
 
 mov           ebx,dword ptr[esp + 01ch]
 add           ebx,dword ptr[edx]
 
 push          edx

 mov           eax,dword ptr[edx + 04h] ;SizeOfBlock
 xor           edx,edx
 mov           ecx,02h                                            
 sub           eax,08h
 idiv          cx
 
 pop           edx
 
 lea           esi,dword ptr[edx + 08h]
 
 xor           ecx,ecx
 
@@:
 cmp           ecx,eax
 jnb           __break1  ;if(ecx >= eax)  __break1
 movzx         edi,word ptr[esi]
 mov           eax,edi
 shr           eax,0ch
 
 cmp           eax,IMAGE_REL_BASED_HIGHLOW    ;if (eax == IMAGE_REL_BASED_HIGHLOW)
 je            __set
 
__continue:
 add           esi,sizeof word
 inc           ecx
 jmp           @b
 
__set: 
 and           edi,0fffh
 mov           eax,dword ptr[esp + 018h] ;delta
 add           dword ptr[ebx + edi],eax   ;chck short
 jmp           __continue
 
__break1: 
  
 add           edx,dword ptr[edx + 04h] ;SizeOfBlock
 jmp           __l1
 
__break:
 pop           edi
 pop           esi
 ;...
 
 pop           ecx
 pop           edx
 pop           ebx
 ret           08h

write_sections:                  ;use ecx,ebx [esp+4]h_proc,[esp+8]nt    ;out:void fck errors
 push          ecx
 push          ebx
 push          edx
 mov           ebx,dword ptr[esp+014h]     ;ebx=nt
 lea           ebx,dword ptr[ebx + 04h]    ;FileHeader     
 movzx         ecx,word ptr[ebx + 02h]      ;NumberOfSections
 mov           ebx,dword ptr[esp + 014h]   ;ebx=nt
 lea           ebx,dword ptr[ebx + 018h]   ;OptionalHeader
 mov           edx,dword ptr[ebx + 01ch]   ;valloc2 imagebase
 add           ebx,sizeof IMAGE_OPTIONAL_HEADER          ;eax=section

@@:
 push          edx
 push          edi
 push          ecx
 
 push          0
 push          dword ptr[ebx + 010h] ;SizeOfRawData
 
 mov           eax,edi                     ;valloc1 mz
 add           eax,dword ptr[ebx + 014h] ;PointerToRawData
 push          eax
 
 mov           eax,edx
 add           eax,dword ptr[ebx + 0ch] ;VirtualAddress;PointerToRawData
 push          eax
 
 push          dword ptr[esp+02ch]
 call          WriteProcessMemory
 pop           ecx
 
 add           ebx,sizeof IMAGE_SECTION_HEADER

 pop           edi 
 pop           edx
   ;...
 loopne        @b
 ;...
 pop           edx
 pop           ebx
 pop           ecx
 ret           08h

error_close:
 push          ebx
 call          CloseHandle

error:  
 mov           eax,-1
 add           esp,4
 ret

read_file:
 mov           eax,dword ptr[esp+04h];
 push          0
 push          FILE_ATTRIBUTE_NORMAL or \
               FILE_ATTRIBUTE_HIDDEN or \
               FILE_ATTRIBUTE_SYSTEM
 push          OPEN_EXISTING
 push          0
 push          FILE_SHARE_READ
 push          GENERIC_READ
 push          eax
 call          CreateFile
 ret           04h
 
start:
 sub           esp,4
 
 push          offset f_name
 call          read_file
 or            eax,eax
 je            error
 cmp           eax,INVALID_HANDLE_VALUE
 je            error
 mov           ebx,eax
 
 push          0
 push          eax
 call          GetFileSize             ;ebx=f_hnd eax=f_size
 cmp           eax,INVALID_FILE_SIZE
 je            error_close
 mov           ecx,eax                 ;ecx=eax=f_size
 
 push          ecx
 
 push          PAGE_READWRITE
 push          MEM_COMMIT
 push          ecx
 push          0
 call          VirtualAlloc            ;eax=h_virtual_alloc
 or            eax,eax
 pop           ecx
 je            error_close
 
 mov           edi,eax                     ;store h_virtual_alloc 
 
 push          ebx
 
 push          0
 push          0
 push          ecx                     ;size
 push          eax                     ;h_virtual_alloc
 push          ebx                     ;f_hnd
 call          ReadFile
 or            eax,eax
 pop           ebx
 je            error_close
 
 ;get nt_header from h_virtual_alloc
 mov           edx,edi                     ;edi v_alloc
 add           edx,dword ptr[edi + 03ch]   ;e_lfanew (PE header Nt)

 mov           dword ptr[esp],edx    ;store nt in local var 
 
 lea           edx,dword ptr[edx + 018h]   ;OptionalHeader
  
 ; get sizeOfImage from edx
 mov           ecx,dword ptr[edx + 038h]    ;SizeOfImage 
 
 push          edx
 push          ebx
 call          GetCurrentProcess
 push          eax
 
 ;virtualAlloc
 push          PAGE_EXECUTE_READWRITE
 push          MEM_RESERVE or MEM_COMMIT
 push          ecx
 push          0
 call          VirtualAlloc
 or            eax,eax
 pop           ecx                 ;h_proc
 pop           ebx
 pop           edx
 je            error_close
 
;get (from edx) image-base + adresOfEntryPoint
 
 push          ecx
 mov           ecx,dword ptr[edx + 01ch]  ;ImageBase
 mov           m_delta,eax  
 sub           m_delta,ecx
 pop           ecx
 
 mov           dword ptr[edx + 01ch],eax    ;new ImageBase
 mov           esi,eax                     
 add           esi,dword ptr[edx + 010h]   ;AddressOfEntryPoint       ;esi=funct_ptr
 
 mov           m_entry,esi
 
 ;write header
 push          ecx
 push          edx

 push          0
 push          dword ptr[edx + 03ch]     ;SizeOfHeaders
 push          edi
 push          eax
 push          ecx
 call          WriteProcessMemory
 pop           edx
 pop           ecx
 or            eax,eax
 je            error_close 
 ;write section (nt->FileHeader.NumberOfSections)
 push          dword ptr[esp]
 push          ecx 
 call          write_sections
 
 ;fix relocation !!
 push          dword ptr[edx + 01ch] ;new imageBase
 push          dword ptr[m_delta] 
 call          fix_relocations
 
 ;parse imports && loadLibrary
 ;edx = OptionalHeader
 call          parse_iat
 
 call          dword ptr[m_entry]
 
 add           esp,4

 ret 
 
end start
