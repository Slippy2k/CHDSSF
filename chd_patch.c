// Compile (mingw): gcc -shared -m32 -w ./chd_patch.c -lwinmm -o ./WINM0.dll
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <string.h>
#include "chd_helper.h"
// General Defines

// Static Globals
static unsigned int cpid = NULL;
static DWORD_PTR base_address = NULL;
#define IMAGE_EXE_MODULE_NAME "SSF.exe"
#define IMAGEBASE_RAW_ALIGN 0xC00

#define EXAMPLE_DLL __declspec(dllexport)

static HANDLE ldll;
static int(*libchd_cdrom_open)(int);
static int(*libchd_cdrom_get_toc)(int,unsigned int*);
static int(*libchd_cdrom_read_data)(struct _cdrom_file*,unsigned int,unsigned char*,unsigned int,unsigned char);
static unsigned char* disc_toc = NULL;
static unsigned int disc_toc_size = NULL;


void detour_function4(void * new_adr, int addr)
{
	unsigned int OldProtect = 0;
	unsigned int Temp = 0;
    int call = (int)(new_adr - addr - 5);
    //UNPROTECT(addr, 4096);
	VirtualProtect(addr,4096, PAGE_EXECUTE_READWRITE, &OldProtect);
    
    *((unsigned char*)(addr)) = 0xE8;
    *((int*)(addr + 1)) = call;
    *((unsigned char*)(addr+5)) = 0x90;

	VirtualProtect(addr,4096, OldProtect, &Temp);
}

bswap32(unsigned int x)
{
	return	((x << 24) & 0xff000000 ) |
		((x <<  8) & 0x00ff0000 ) |
		((x >>  8) & 0x0000ff00 ) |
		((x >> 24) & 0x000000ff );
}

unsigned short bswap16(unsigned short x)
{
	/*LINTED*/
	return ((x << 8) & 0xff00) | ((x >> 8) & 0x00ff);
}


void get_toc_data(){
	disc_toc = (unsigned char*)malloc(12+(cdrf.cdtoc.numtrks*8));

	memset(disc_toc,0x00,12+(cdrf.cdtoc.numtrks*8));

	unsigned short toc_sz = 10+(cdrf.cdtoc.numtrks*8);
	toc_sz = bswap16(toc_sz);
	
	memcpy(disc_toc,&toc_sz,2);
	memset(disc_toc+2,0x01,1);
	memset(disc_toc+3,cdrf.cdtoc.numtrks&0xFF,1);
	
	unsigned int toc_buffer_track_offset = 4;
	unsigned int leadout_start = 0;

	for(int i=0;i< cdrf.cdtoc.numtrks;i++){
		unsigned char track_info[8] = {0x00};
		if(cdrf.cdtoc.tracks[i].subtype == 0x01){
			track_info[1] = 0x14;	
		}else{
			track_info[1] = 0x10;	
		}
		
		track_info[2] = i+1;
		unsigned int tis = bswap32(cdrf.cdtoc.tracks[i].physframeofs);
		memcpy(track_info+4,&tis,4);
		memcpy(disc_toc+toc_buffer_track_offset,track_info,8);
		toc_buffer_track_offset+=8;
		leadout_start = cdrf.cdtoc.tracks[i].physframeofs + cdrf.cdtoc.tracks[i].extraframes;

	}
	unsigned char leadout_track[8] = {0x00, 0x10, 0xAA, 0x00,0x00, 0x00, 0x00, 0x00};
	unsigned int tis = bswap32(leadout_start);
	memcpy(leadout_track+4,&tis,4);
	memset(disc_toc+3,cdrf.cdtoc.numtrks&0xFF,1);
	memcpy(disc_toc+toc_buffer_track_offset,leadout_track,8); 
	disc_toc_size = 12+(cdrf.cdtoc.numtrks*8);

}

unsigned char* GetWC(unsigned char* src){
	unsigned int num_chars = strlen(src)+1;
	num_chars*=2;
	unsigned char* dest = (unsigned char*)malloc(num_chars);
	swprintf(dest,L"%hs",src);
	return dest;
}

void load_chd_file(unsigned char*  chd_path){

	int addr = libchd_cdrom_open(chd_path);
	memcpy(&cdrf,addr,sizeof(cdrf));
}

void init_chd_library(){
	ldll = LoadLibrary("libchd.dll");
  	libchd_cdrom_open = GetProcAddress(ldll, "libchd_cdrom_open");
  	libchd_cdrom_get_toc = GetProcAddress(ldll,"libchd_cdrom_get_toc");
  	libchd_cdrom_read_data = GetProcAddress(ldll,"libchd_cdrom_read_data");	
}

/*
	The Saturn Archive.org CHD Audio is Endian-Reversed for... I don't know, it is, we'll swap it while reading it out.
	Yes - I know this is a horrible way to swap this, I'll fix it later.
*/
void bswap_buffer(unsigned char* buffer,unsigned int num_bytes){
	for(int i=0;i<num_bytes;i+=2){
		
		buffer[i] ^= buffer[i+1];
		buffer[i+1] ^= buffer[i];
		buffer[i] ^= buffer[i+1];
	}	
}


void read_disc_data(unsigned char*buffer,unsigned int offset,unsigned int len,unsigned int dtype){
	
	unsigned int lba_sz = 2352;
	unsigned dest_offset = 0;
	unsigned char* tb = (unsigned char*)malloc(2352);
	for(unsigned int i =offset;i<offset+len;i++){
		memset(tb,0x00,2352);
		int retval = libchd_cdrom_read_data(&cdrf, i,tb, dtype,1);
		if(retval == 0){
			libchd_cdrom_read_data(&cdrf,i,tb,7,1);
			bswap_buffer(tb,2352);
		}
		memcpy(buffer+dest_offset,tb,lba_sz);
		dest_offset+=2352;
		
	}
}

typedef struct _SCSI_PASS_THROUGH_DIRECT {
  unsigned short Length;
  unsigned char  ScsiStatus;
  unsigned char  PathId;
  unsigned char  TargetId;
  unsigned char  Lun;
  unsigned char  CdbLength;
  unsigned char  SenseInfoLength;
  unsigned char  DataIn;
  unsigned int  DataTransferLength;
  unsigned int  TimeOutValue;
  void*  DataBuffer;
  unsigned int  SenseInfoOffset;
  unsigned char  Cdb[16];
}SCSI_PASS_THROUGH_DIRECT, *PSCSI_PASS_THROUGH_DIRECT;

static SCSI_PASS_THROUGH_DIRECT sptd;
static SCSI_PASS_THROUGH_DIRECT sptd2;
unsigned char drive_id[] =
{
	0x05, 0x80, 0x00, 0x32, 0x5B, 0x00, 0x00, 0x00, 0x43, 0x48, 0x44, 0x44, 0x72, 0x69, 0x76, 0x65, 
	0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
};





unsigned char senseinfo[18] = {
	0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00
};

unsigned char disc_thing_1(int hDevice,unsigned int dwIoControlCode,unsigned char* lpInBuffer,unsigned int nInBufferSize,unsigned char* lpOutBuffer,unsigned int nOutBufferSize,unsigned int * lpBytesReturned,unsigned int lpOverlapped){
	unsigned char op = *(unsigned char*)(lpInBuffer+6);
	char info_buffer[4096] = {0x00};
	    
    
    memcpy(&sptd,lpInBuffer,sizeof(sptd));
    unsigned int operation_code = sptd.Cdb[0];
    char info_msg[1024]={0x00};
    unsigned int offset;
    unsigned int lba;
    unsigned int num_blocks;
    unsigned int removal_set;
    FILE *fp;
    switch(operation_code){
    	case 0x00:
			OutputDebugString("TEST UNIT READY");
    		sptd.SenseInfoLength = 0;
    		memcpy(lpOutBuffer,&sptd,sptd.Length);
    		return 1;
    		break;

    	case 0x03:
    		OutputDebugString("REQUEST SENSE");
    		sptd.Lun = 1;
     		sptd.SenseInfoLength = 0;
     		memcpy(sptd.DataBuffer,senseinfo,sizeof(senseinfo));
    		memcpy(lpOutBuffer,&sptd,sptd.Length);   
    		return 1;		
    		break;
    	case 0x12:
    		OutputDebugString("INQUIRY");
    		memcpy(sptd.DataBuffer,drive_id,32);
    		sptd.Lun = 1;
    		sptd.SenseInfoLength = 0;
    		memcpy(lpOutBuffer,&sptd,sptd.Length);
    		return 1;
    		break;
    	case 0x43:
    		OutputDebugString("READ TOC/PMA/ATIP");
    		memcpy(sptd.DataBuffer,disc_toc,disc_toc_size);
    		sptd.DataTransferLength = disc_toc_size;
    		sptd.SenseInfoLength = 0;
    		memcpy(lpOutBuffer,&sptd,sptd.Length);  	
    		return 1;	
    		break;
    	case 0x1E:
    		
    		
    		memcpy(&removal_set,sptd.Cdb+4,4);
    		sprintf(info_msg,"PREVENT ALLOW MEDIUM REMOVAL set to %d",removal_set);
    		OutputDebugString(info_msg);
    		sptd.SenseInfoLength = 0;
    		memcpy(lpOutBuffer,&sptd,sptd.Length);
    		return 1;
    		break;
    	case 0xBE:
    		
			
			// Copy To Data Buffer
			
			memcpy(&offset,sptd.Cdb+2,4);
			memcpy(&lba,sptd.Cdb+2,4);
			offset = bswap32(offset);
			lba = bswap32(lba);
			offset *= 2352;
			unsigned int num_bytes = sptd.Cdb[8];
			num_bytes *= 2352;
    		sptd.SenseInfoLength = 0;
    		num_blocks = sptd.Cdb[8];
    		//sprintf(info_msg,"Disc Read Offset: %04X Length: %d",lba,num_blocks);
    		OutputDebugString(info_msg);
    		unsigned char*dbuf=(unsigned char*)malloc(num_blocks*2352);
    		read_disc_data(dbuf,lba,num_blocks,1);
    	
    		memcpy(sptd.DataBuffer,dbuf,num_bytes);
		    free(dbuf);

    		memcpy(lpOutBuffer,&sptd,sptd.Length);			
    		return 1; 
    		break;
    	default:
		sprintf(info_buffer,"Unknown SPTD Operation Code %#x",operation_code);
    	OutputDebugString(info_buffer);
    	break;
    }
    
	return DeviceIoControl(hDevice,dwIoControlCode,lpInBuffer,nInBufferSize,lpOutBuffer,nOutBufferSize,lpBytesReturned,lpOverlapped);
}

void patch_memory_set(unsigned int addr, unsigned char buff, unsigned int sz){
	unsigned int Temp = 0;
	unsigned int OldProtect = 0;
	VirtualProtect(addr, sz, PAGE_EXECUTE_READWRITE, &OldProtect);
	memset(addr,buff,sz);
	VirtualProtect(addr, sz, OldProtect, &Temp);
}

void patch_binary(){
    char buf[128]={0x00};
	sprintf(buf,"Offset is %04X",base_address+0x1FC381);
	OutputDebugString(buf);
	detour_function4(&disc_thing_1,base_address+0x1FC381);
	detour_function4(&disc_thing_1,base_address+0x1FC790);
	patch_memory_set(base_address+0x1FC6BF,0x90,6);
}


// Returns base offset of the executable module with the raw alignment offset.
void resolve_base_address(void){
	if(cpid == NULL){
		cpid = GetCurrentProcessId();
		unsigned char generic_debug_msgbuf[1024] = {0x00};
		sprintf(generic_debug_msgbuf,"Patch: PID is %d",cpid);
		OutputDebugString(generic_debug_msgbuf);
		if(cpid == NULL){
			OutputDebugString("FATAL: Couldn't Get Process ID");
			exit(1);
		}
		// Get Base Address for Module
		base_address = (DWORD_PTR)GetModuleHandleA(IMAGE_EXE_MODULE_NAME) + IMAGEBASE_RAW_ALIGN;
	}
}


// Entry-Point Function
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){
    if (fdwReason == DLL_PROCESS_ATTACH){
		//ini_parse("chd.ini", handler, &config);
		resolve_base_address();
		patch_binary();
		OutputDebugString("CHD_PATCH: We Attached!!!");
		init_chd_library();

		// Get Target CHD Image.
		LPCWSTR cmd;
		cmd = GetCommandLineW();
		unsigned int num_args;
		LPCWSTR* args = CommandLineToArgvW(cmd,&num_args);
		// Load the CHD Image object.
		load_chd_file(args[1]);
		// Get the TOC, Might as well do that now...
		get_toc_data();
    }
    if (fdwReason == DLL_PROCESS_DETACH){}
    return TRUE;
}

// Piggyback Functions
unsigned int EXAMPLE_DLL ximeBeginPeriod(unsigned int uPeriod){
	return timeBeginPeriod(uPeriod);
}

// Piggyback Functions
unsigned int EXAMPLE_DLL ximeEndPeriod(unsigned int uPeriod){
	return timeEndPeriod(uPeriod);
}

unsigned int EXAMPLE_DLL ximeGetTime(void){
	return timeGetTime();
}