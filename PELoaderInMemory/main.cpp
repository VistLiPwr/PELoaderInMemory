#include<windows.h>
#include"peBase.hpp"



int main(int argc,char *argv[]) {
	if (argc != 2) {
		//剥离文件名
		printf("The Current Usage is: %s [Exe Path]", strrchr(argv[0], '\\') ? strrchr(argv[0], '\\') + 1 : argv[0]);
		getchar();
		return 0;
	}
}