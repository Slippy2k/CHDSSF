// CHDTEST
// Compile (mingw): gcc -m32 -w ./chdtest.c -o ./chdtest.exe
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include "chd_helper.h"






	static HANDLE ldll;
	
  	static int(*libchd_cdrom_open)(int);
  	static int(*libchd_cdrom_get_toc)(int,unsigned int*);
  	static int(*libchd_cdrom_read_data)(struct _cdrom_file*,unsigned int,unsigned char*,unsigned int,unsigned char);


/*
	The Saturn Archive.org CHD Audio is Endian-Reversed for... I don't know, it is, we'll swap it while reading it out.
	Yes - I know this is a horrible way to swap this, I'll fix it later.
*/
void bswap_buffer(unsigned char* buffer,unsigned int num_bytes){
	for(int i=0;i<num_bytes;i+=2){
		unsigned char t = buffer[i+1];
		buffer[i+1] = buffer[i];
		buffer[i] = t;

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

static unsigned char* disc_toc = NULL;
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

int main(){
	LPCWSTR cmd;
	cmd = GetCommandLineW();
	unsigned int num_args;
	LPCWSTR* args = CommandLineToArgvW(cmd,&num_args);

	
	init_chd_library();
  	load_chd_file(args[1]);
	
	
	get_toc_data();
	

	//unsigned char* buffer = (unsigned char*)malloc(2352*8);
	//read_disc_data(buffer,0x1034,8,7); // TODO - figure out track value.
	//DumpHex(buffer,2352);

	return 0;
}