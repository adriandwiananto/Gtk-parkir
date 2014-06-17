#include "header.h"

/* function for generating random number using /dev/random */
int random_number_generator(int min_number, int max_number)
{
	int randomData = open("/dev/random", O_RDONLY);
	int myRandomInteger = max_number + 1;
	ssize_t result;
	
	while(myRandomInteger > max_number)
	{
		myRandomInteger = 0;
		result = read(randomData, (char*)&myRandomInteger, (sizeof myRandomInteger));
		if (result < 0)
		{
			error_message("Failed to read /dev/random");
		}
				
		myRandomInteger %= max_number;
		if(myRandomInteger < min_number)
		{
			myRandomInteger = max_number + 1;
		}
	}
	close(randomData);
	
	return myRandomInteger;
}

void print_array_inHex(const char* caption, unsigned char* array, int size)
{
	int i = 0;
	printf("%s\n",caption);
	for(i = 0; i<size; i++) printf("%02X ", array[i]);
	printf("\n");
}

double current_time_in_mill()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	
	return (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
}

/* hex written as string to binary Array */
void hexstrToBinArr(unsigned char* dest, gchar* source, gsize destlength)
{
	int i;
	
	for (i=0;i<destlength;i++) 
	{
		int value;
		sscanf(source+2*i,"%02x",&value);
		dest[i] = (unsigned char)value;
	}
}
