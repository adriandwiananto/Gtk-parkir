#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <signal.h>
#include "CVAPIV01_DESFire.h"

#define DEVICE_ADDRESS	(0)

//INS preprocessor
#define SELECT 			(0xA4)
#define READ_BINARY		(0xB0)
#define UPDATE_BINARY	(0xD6)

bool complete = false;
int force_exit = 0;
bool PICC_init = false;
bool PICC_NDEF_detection = false;

static void
intr_hdlr(int sig)
{
	fprintf(stdout,"killed with %d signal\n", sig);
	force_exit = 2;
}

void print_data(unsigned char *Data, unsigned char Len, const char *Type)
{
	int i=0;
	bool success = false;
	
	if (!strcmp(Type,"RetData"))
	{
		Len+=1;
		fprintf(stdout,"Ret Data:\n");
		success = true;
	}
	else if (!strcmp(Type,"Response"))
	{
		fprintf(stdout,"Response Data:\n");
		success = true;
	}
	else if (!strcmp(Type,"NDEF"))
	{
		fprintf(stdout,"NDEF Data:\n");
		success = true;
	}
	else if (!strcmp(Type,"Result"))
	{
		for(i=0;i<Len;i++)
		{
			fprintf(stdout,"%02X", Data[i]);
		}
		fprintf(stdout,"\n");
		success = false;
	}
	
	if (success == true)
	{
		for(i=0;i<Len;i++)
		{
			fprintf(stdout,"%02X ", Data[i]);
			if(!((i+1)%8))fprintf(stdout,"\n");
		}
		fprintf(stdout,"\n");
	}
}

/* hex written as string to binary Array */
void hexstrToBinArr(unsigned char* dest, char* source, int destlength)
{
	int i;
	
	for (i=0;i<destlength;i++) 
	{
		int value;
		sscanf(source+2*i,"%02x",&value);
		dest[i] = (unsigned char)value;
	}
}

int main(int argc, char *argv[])
{
	struct sigaction ctrlcHandler;
    memset(&ctrlcHandler, 0, sizeof(struct sigaction));
    ctrlcHandler.sa_handler = intr_hdlr;
    sigaction(SIGINT, &ctrlcHandler, NULL);
    
    struct sigaction killHandler;
    memset(&killHandler, 0, sizeof(struct sigaction));
    killHandler.sa_handler = intr_hdlr;
    sigaction(SIGTERM, &killHandler, NULL);
    
    bool valid_arg = false;
	
	if (argc == 2)
	{
		if(strlen(argv[1]) == 110){
			valid_arg = true;
		}
	}
	
	if (valid_arg == false)
	{
		fprintf(stderr,"Can not start NFC! wrong argument!\n");
		return 5;
	}
	
	//Reader connect with USB interface
	CV_SetCommunicationType(1);
	
	int Addr=99;
	int &CurAddr = Addr;
	char SerialNum[8];
	bool open_reader = false;
	int open_count = 0;
	while(!open_reader)
	{
		if(!GetSerialNum(DEVICE_ADDRESS, CurAddr, SerialNum))
		{
			fprintf(stdout,"Address: %d, SN: %s\n", Addr, SerialNum);
			open_reader = true;
		}
		else
		{
			if(open_count < 5)
			{
				fprintf(stderr, "fail to initialize reader. retry attempt\n");
			}
			CloseComm();
			CV_SetCommunicationType(1);
			if(open_count >= 5)
			{
				fprintf(stderr, "fail to initialize reader. please reconnect\n");
				return 1;
			}
		}
		fprintf(stdout,"opencount:%d\n",open_count);
		open_count++;
		usleep(10*1000);
	}
	
	unsigned char All_Read_Data[0x52];
	
	const unsigned char Receipt_Header[0x1B] = {
		0x00,0x50, //NDEF Length
		//NDEF Header: 0xD2 define ndef
		//0x16 "emoney/merchantReceipt" length
		//0x37 Payload length
		0xD2,0x16,0x37, 
		0x65,0x6d,0x6f,0x6e,0x65,0x79,0x2f,0x6d,
		0x65,0x72,0x63,0x68,0x61,0x6e,0x74,0x52,
		0x65,0x63,0x65,0x69,0x70,0x74,
	};

	unsigned char Receipt_Payload[0x37];
	hexstrToBinArr(Receipt_Payload, argv[1], 0x37);
	
	memcpy(All_Read_Data, Receipt_Header, 0x1B);
	memcpy(All_Read_Data+0x1B, Receipt_Payload, 0x37);
	
	//~ const unsigned char All_Read_Data[0x52] = {
		//~ 0x00,0x50, //NDEF Length
		//~ //NDEF Header: 0xD2 define ndef
		//~ //0x16 "emoney/merchantReceipt" length
		//~ //0x37 Payload length
		//~ 0xD2,0x16,0x37, 
		//~ 0x65,0x6d,0x6f,0x6e,0x65,0x79,0x2f,0x6d,
		//~ 0x65,0x72,0x63,0x68,0x61,0x6e,0x74,0x52,
		//~ 0x65,0x63,0x65,0x69,0x70,0x74,
		//~ //NDEF Payload
		//~ 0x37,0x01,0x01,0x00,0x93,0x00,0x00,0xC5,
		//~ 0x2D,0x06,0x36,0x4C,0xC4,0xBF,0x2D,0x2B,
		//~ 0x34,0x07,0xE6,0xC8,0xE2,0x70,0x51,0x1B,
		//~ 0xD1,0x56,0xFC,0x51,0x22,0xC6,0xDA,0x73,
		//~ 0xB8,0xFE,0x6C,0x43,0xDA,0x77,0x08,0x66,
		//~ 0x2B,0xEB,0x5A,0x20,0xDB,0x8C,0x8F,0x56,
		//~ 0x10,0x36,0xC3,0x29,0x7C,0x2A,0xCE
	//~ };
	
	unsigned char MParam[6];
	MParam[0] = 0x01;
	MParam[1] = 0x04;
	MParam[2] = 0x06;
	MParam[3] = 0x06;
	MParam[4] = 0x06;
	MParam[5] = 0x20;
	
	unsigned char FParam[18];
	memset(FParam, 0, 18);
	
	unsigned char NFCID3t[10];
	memset(FParam, 0, 10);
	NFCID3t[1] = 0x06;
	NFCID3t[2] = 0x06;
	NFCID3t[3] = 0x06;
	
	unsigned char RetData[262];
	memset(RetData, 0, 262);
	
	unsigned char empty = 0;
	
	unsigned char TgResponse[262];
	memset(TgResponse, 0, 262);
	
	unsigned char TgResLen;
	
	bool PICC_init = false;
	while (!complete && !force_exit)
	{
		PICC_init = false;
		while(!PICC_init && !force_exit)
		{
			//~ usleep(300*1000);
			//~ int NFC_Picc_Init (	int DeviceAddress, unsigned char Mode, unsigned char* MParam,
								//~ unsigned char* FParam, unsigned char* NFCID3t, unsigned char GtLen,
								//~ unsigned char* Gt, unsigned char TkLen, unsigned char* Tk, 
								//~ unsigned char* RetData)
			if(!NFC_Picc_Init(DEVICE_ADDRESS, 0x05, MParam, FParam, NFCID3t, empty, &empty, empty, &empty, RetData))
			{
				if(RetData[0] != 0)
				{
					fprintf(stdout,"Init OK!\n");
					print_data(RetData,RetData[0],"RetData");
					PICC_init = true;
				}
				else fprintf(stderr,"Init fail!\n");
			}
			else fprintf(stderr,"Init func call fail!\n");
		}
	
		int i;
		unsigned char INS;

		PICC_NDEF_detection = false;
		while(!PICC_NDEF_detection && !force_exit)
		{
			memset(RetData, 0, 262);
			memset(TgResponse, 0, 262);
			if(!NFC_Picc_Command(DEVICE_ADDRESS, RetData))
			{
				fprintf(stdout,"NFC Picc Command OK!\n");
				print_data(RetData,RetData[0],"RetData");
				
				INS = RetData[3];
				
				switch(INS)
				{
					case SELECT:
					{
						bool Flag = false;
						unsigned char Lc;
						Lc = RetData[6];
						unsigned char DataBytes[Lc];

						if (Lc)
						{
							for(i=0;i<Lc;i++)DataBytes[i]=RetData[7+i];
						}
						
						if (Lc == 7) //NDEF Tag Application Select
						{
							unsigned char CmpData[7] = {0xD2,0x76,0x00,0x00,0x85,0x01,0x01};

							for(i=0;i<7;i++)
							{
								if(DataBytes[i]==CmpData[i])Flag = true;
								else Flag = false;
							}
							
							if(Flag == true) //Type 4 tag ver2.0
							{
								TgResponse[0] = 0x6A;
								TgResponse[1] = 0x82;
								TgResLen = 2;
							}
							else //Type 4 tag ver1.0
							{
								TgResponse[0] = 0x90;
								TgResponse[1] = 0x00;
								TgResLen = 2;
							}	
						}
						else if (Lc == 2)
						{
							//Capability Container & NDEF Select command
							if(DataBytes[0] == 0xE1)
							{
								if(DataBytes[1] == 0x03 || DataBytes[1] == 0x04)
									Flag = true;
								else
									Flag = false;
							}
							else Flag = false;
							
							if(Flag == true)
							{
								TgResponse[0] = 0x90;
								TgResponse[1] = 0x00;
								TgResLen = 2;
							}
							else
							{
								TgResponse[0] = 0x6A;
								TgResponse[1] = 0x82;
								TgResLen = 2;
							}	
						}
						else
						{
							TgResponse[0] = 0x6F;
							TgResponse[1] = 0x00;
							TgResLen = 2;
						}
						break;
					}
					
					case READ_BINARY:
					{
						unsigned char Le;
						Le = RetData[6];
						
						if (Le == 0x0F) //Read binary data from CC file
						{
							//See NFCForum Tech Spec Type 4 Tag 2.0
							//Page 29 (Appendix C.1, Detection of NDEF Message)
							//Slight modification in Max NDEF Size (50 -> 1024)
							unsigned char ResBuff[17] 	= { 0x00,0x0F,0x10,0x00,
															0x3B,0x00,0x34,0x04,
															0x06,0xE1,0x04,0x04,
															0x00,0x00,0x00,0x90,
															0x00 };
							memcpy(TgResponse, ResBuff, 17);
							TgResLen = 17;
						}
						else if (Le == 2) //Read NDEF Length
						{
							//0x0052 = Total NDEF length + 2 byte (for NLEN)
							unsigned char ResBuff[4]	= {	0x00,0x52,0x90,0x00 };
							memcpy(TgResponse, ResBuff, 4);
							TgResLen = 4;
						}
						else
						{
							if (Le)
							{
								unsigned char P2;
								P2 = RetData[5];
								memcpy(TgResponse, All_Read_Data+P2, Le);
								
								unsigned char SW1SW2[2] = {0x90,0x00};
								memcpy(TgResponse+Le, SW1SW2, 2);
								TgResLen = Le+2;
								
								//0x52 is All_Read_Data length
								int TotalRead = RetData[4] + RetData[5] + RetData[6];
								printf("Total Read: %d\n\n",TotalRead);
								if(TotalRead == 0x52)
								{
									complete = true;
									printf("Complete True\n");
								}
							}
							else
							{
								TgResponse[0] = 0x6F;
								TgResponse[1] = 0x00;
								TgResLen = 2;
							}
						}
						break;
					}
					
					case UPDATE_BINARY:
					{
						unsigned char Lc = RetData[6];
						unsigned char RcvdNDEF[262];

						memset(RcvdNDEF, 0, 262);
						for(i=0;i<(Lc-2);i++)RcvdNDEF[i] = RetData[9+i];
						print_data(RcvdNDEF, Lc-2, "NDEF");
						
						TgResponse[0] = 0x90;
						TgResponse[1] = 0x00;
						TgResLen = 2;
						
						break;
					}
					
					default:
						TgResponse[0] = 0x6F;
						TgResponse[1] = 0x00;
						TgResLen = 2;
						break;
				}
				
				if(!NFC_Picc_Response(DEVICE_ADDRESS, TgResLen, TgResponse, RetData))
				{
					fprintf(stdout,"NFC Picc Response OK!\n");
					print_data(TgResponse,TgResLen,"Response");
					fprintf(stdout,"\n");
				}
				else
				{
					fprintf(stderr,"NFC Picc Response Fail!\n");
					force_exit = 3;
				}
			}
			else
			{
				fprintf(stderr,"NFC Picc Command Fail!\n");
				PICC_NDEF_detection = true;
			}
		}
	}
	
	switch(force_exit){
		case 0:
			break;
		default:
			return force_exit;
	}
	
	fprintf(stdout,"program exit smoothly\n");
	
	if (complete)
	{
		fprintf(stdout,"DATA:Success\n");
		return 0;
	}
	
	return 2;
}
