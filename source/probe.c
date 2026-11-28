// Исправление ввода кириллицы NMS: динамический поиск в секции .text.
typedef unsigned long DWORD; typedef unsigned long long U64; typedef void* HANDLE; typedef unsigned short W;
#define API __declspec(dllimport)
API void* GetModuleHandleW(const W*); API int VirtualProtect(void*,U64,DWORD,DWORD*); API int FlushInstructionCache(HANDLE,const void*,U64); API HANDLE GetCurrentProcess(void); API HANDLE CreateThread(void*,U64,DWORD(*)(void*),void*,DWORD,DWORD*); API int CloseHandle(HANDLE); API void Sleep(DWORD); API HANDLE CreateFileW(const W*,DWORD,DWORD,void*,DWORD,DWORD,HANDLE); API int WriteFile(HANDLE,const void*,DWORD,DWORD*,void*);
U64 resume_yes,resume_no,insert_text; void probe(void);
static HANDLE logh;
static void (*volatile probe_address)(void)=probe;
static void out(const char*s){DWORD n=0,w;while(s[n])n++;WriteFile(logh,s,n,&w,0);}
// Поиск строго одного совпадения в исполняемой секции PE.
static unsigned char* unique(const unsigned char* sig, unsigned len){
 unsigned char* base=GetModuleHandleW(0),*pe,*sec,*start,*found=0;
 unsigned size,i,j,n,offset;
 if(!base || *(W*)base!=0x5a4d)return 0;
 pe=base+*(DWORD*)(base+60);
 if(*(DWORD*)pe!=0x4550 || *(W*)(pe+4)!=0x8664)return 0;
 n=*(W*)(pe+6);sec=pe+24+*(W*)(pe+20);
 for(i=0;i<n;i++,sec+=40){
  if(*(DWORD*)sec!=0x7865742e || sec[4]!='t' || sec[5]!=0)continue;
  size=*(DWORD*)(sec+8);offset=*(DWORD*)(sec+12);
  if(!(*(DWORD*)(sec+36)&0x20000000) || size<len || offset>*(DWORD*)(pe+80) || size>*(DWORD*)(pe+80)-offset)return 0;
  start=base+offset;
  for(j=0;j<=size-len;j++){
   unsigned k=0;while(k<len && start[j+k]==sig[k])k++;
   if(k==len){if(found)return 0;found=start+j;}
  }
  return found;
 }
 return 0;
}
static DWORD worker(void* unused){
 unsigned char* p;
 const unsigned char expected[]={0x49,0x2b,0xc2,0x49,0x3b,0xc7,0x75,0x0c,0x41,0x0f,0xbe,0x12,0x48,0x8b,0xce};
 unsigned char patch[15]={0xff,0x25,0,0,0,0}; U64 dest=(U64)probe_address; DWORD old,tmp; unsigned i;
 logh=CreateFileW((const W*)L"NMS_CyrillicInputFix.log",0x40000000,3,0,2,0x80,0); if(logh==(HANDLE)-1)return 0;
 out("NMS Cyrillic Input Fix 1.1.0-test\r\n");
 p=unique(expected,sizeof(expected));
 if(!p){out("Signature mismatch; no patch\r\n");return 0;}

 const unsigned char ins[]={0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x48,0x89,0x7c,0x24,0x20,0x41,0x56,0x48,0x83,0xec,0x30,0x48,0x8b,0x99,0x38,0x06,0,0,0x48,0x8b,0xf1,0x48,0x83,0xc1,0x08,0x41,0x8b,0xf8,0x4c,0x8b,0xf2,0xe8};
 insert_text=(U64)unique(ins,sizeof(ins));
 if(!insert_text || p[15]!=0xe8 || p[20]!=0x4c || p[21]!=0x8b || p[22]!=0xd3){out("Insert signature mismatch; no patch\r\n");return 0;}
 resume_yes=(U64)(p+15);resume_no=(U64)(p+20);
 // Второй фильтр удаляет байты UTF-8 после вставки.
 unsigned char* filter;
 const unsigned char filter_sig[]={0x0f,0xbe,0xcb,0x48,0x8d,0x76,0x01,0x83,0xf9,0xff,0x7c,0x1f,0x80,0xfb,0x20,0x74,0x0a};
 DWORD filter_old;
 filter=unique(filter_sig,sizeof(filter_sig));
 if(!filter){out("Filter signature mismatch; no patch\r\n");return 0;}
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
