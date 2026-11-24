// Исправление ввода кириллицы NMS, сборка 185034.
typedef unsigned long DWORD; typedef unsigned long long U64; typedef void* HANDLE; typedef unsigned short W;
#define API __declspec(dllimport)
API void* GetModuleHandleW(const W*); API int VirtualProtect(void*,U64,DWORD,DWORD*); API int FlushInstructionCache(HANDLE,const void*,U64); API HANDLE GetCurrentProcess(void); API HANDLE CreateThread(void*,U64,DWORD(*)(void*),void*,DWORD,DWORD*); API int CloseHandle(HANDLE); API void Sleep(DWORD); API HANDLE CreateFileW(const W*,DWORD,DWORD,void*,DWORD,DWORD,HANDLE); API int WriteFile(HANDLE,const void*,DWORD,DWORD*,void*);
U64 resume_yes,resume_no,insert_text; void probe(void);
static HANDLE logh;
static void (*volatile probe_address)(void)=probe;
static void out(const char*s){DWORD n=0,w;while(s[n])n++;WriteFile(logh,s,n,&w,0);}
static DWORD worker(void* unused){
 unsigned char* p=(unsigned char*)GetModuleHandleW(0)+0x6EEE27;
 const unsigned char expected[]={0x49,0x2b,0xc2,0x49,0x3b,0xc7,0x75,0x0c,0x41,0x0f,0xbe,0x12,0x48,0x8b,0xce};
 unsigned char patch[15]={0xff,0x25,0,0,0,0}; U64 dest=(U64)probe_address; DWORD old,tmp; unsigned i;
 logh=CreateFileW((const W*)L"NMS_CyrillicInputFix.log",0x40000000,3,0,2,0x80,0); if(logh==(HANDLE)-1)return 0;
 out("NMS Cyrillic Input Fix 1.0.0\r\n");
 for(i=0;i<15;i++)if(p[i]!=expected[i]){out("Signature mismatch; no patch\r\n");return 0;}
 insert_text=(U64)GetModuleHandleW(0)+0x2E5B7D0;
 const unsigned char ins[]={0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x48,0x89,0x7c,0x24,0x20,0x41,0x56,0x48,0x83,0xec,0x30};
 for(i=0;i<sizeof(ins);i++)if(((unsigned char*)insert_text)[i]!=ins[i]){out("Insert signature mismatch; no patch\r\n");return 0;}
 resume_yes=(U64)(p+15);resume_no=(U64)(p+20);
 // Второй фильтр удаляет байты UTF-8 после вставки.
 unsigned char* filter=(unsigned char*)GetModuleHandleW(0)+0x2E5FB81;
 const unsigned char filter_sig[]={0x0f,0xbe,0xcb,0x48,0x8d,0x76,0x01,0x83,0xf9,0xff,0x7c,0x1f,0x80,0xfb,0x20,0x74,0x0a};
 DWORD filter_old;
 for(i=0;i<sizeof(filter_sig);i++)if(filter[i]!=filter_sig[i]){out("Filter signature mismatch; no patch\r\n");return 0;}
 for(i=0;i<8;i++)patch[6+i]=(unsigned char)(dest>>(8*i));patch[14]=0x90;
 if(!VirtualProtect(p,15,0x40,&old)){out("VirtualProtect failed\r\n");return 0;}
 if(!VirtualProtect(filter+11,1,0x40,&filter_old)){VirtualProtect(p,15,old,&tmp);out("Filter protect failed; no patch\r\n");return 0;}
 // JL теперь ведёт к копированию байта, а не к его пропуску.
 ((volatile unsigned char*)filter)[11]=0x0f;
 FlushInstructionCache(GetCurrentProcess(),filter+11,1);
 VirtualProtect(filter+11,1,filter_old,&tmp);
 for(i=0;i<15;i++)((volatile unsigned char*)p)[i]=patch[i];
 out("UTF-8 byte filter patched\r\n");
 FlushInstructionCache(GetCurrentProcess(),p,15);VirtualProtect(p,15,old,&tmp);out("Fix active\r\n");
 CloseHandle(logh); return 0;
}
int DllMain(HANDLE h,DWORD reason,void* r){if(reason==1){HANDLE t=CreateThread(0,0,worker,0,0,0);if(t)CloseHandle(t);}return 1;}
