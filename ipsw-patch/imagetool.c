#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xpwn/libxpwn.h>
#include <xpwn/ibootim.h>
#include <xpwn/nor_files.h>
#include "abstractfile.h"

void print_usage() {
	XLOG(0, "usage:\timagetool extract <source.img2/3> <destination.png> [iv] [key]\n");
	XLOG(0, "usage:\timagetool inject <source.png> <destination.img2/3> <template.img2/3> [iv] [key]\n");
}

int image_inject(const char* source, const char* destination, const char* template, unsigned int* iv, unsigned int* key) {
	AbstractFile* png = createAbstractFileFromFile(fopen(source, "rb"));
	AbstractFile* img = createAbstractFileFromFile(fopen(template, "rb"));
	AbstractFile* dst = createAbstractFileFromFile(fopen(destination, "wb"));

	size_t size = 0;
	void* buffer = replaceBootImage(img, key, iv, png, &size);
	dst->write(dst, buffer, size);
	dst->close(dst);
	
	return 0;
}

int image_extract(const char* source, const char* destination, unsigned int* iv, unsigned int* key) {
	AbstractFile* img = createAbstractFileFromFile(fopen(source, "rb"));
	if(img != NULL) {
		if(convertToPNG(img, key, iv, destination) < 0) {
			XLOG(1, "error converting img to png");
		}
	}
	
	return 0;
}


int main(int argc, char* argv[]) {
	init_libxpwn();
	
	if(argc < 4) {
		print_usage();
		return 0;
	}

	size_t bytes = 0;
	unsigned int* iv = NULL;
	unsigned int* key = NULL;

	if(strcmp(argv[1], "inject") == 0) {
		if(argc < 5) {
			print_usage();
			return 0;
		}
		
		if(argc >= 7) {
			hexToInts(argv[5], &iv, &bytes);
			hexToInts(argv[6], &key, &bytes);
		}
		
		image_inject(argv[2], argv[3], argv[4], iv, key);
		
	} else if(strcmp(argv[1], "extract") == 0) {
		if(argc >= 6) {
			hexToInts(argv[4], &iv, &bytes);
			hexToInts(argv[5], &key, &bytes);
		}
		
		image_extract(argv[2], argv[3], iv, key);
	}
	
	return 0;
}

