/* return list
 * 0 : normal
 * 1 : USB reader initialization error
 * 2 : killed by signal (SIGTERM / SIGINT)
 * 3 : NFC PICC Response fail (APDU Transaction Error)
 * 4 : NFC PICC Command fail (APDU Transaction Error)
 * 5 : program initialization error
 * 6 : SESN did not match
 * 7 : Invalid payload data (encrypt / decrypt error)
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <signal.h>
#include <inttypes.h>
#include <libconfig.h>
#include <openssl/sha.h>
#include <sys/wait.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "CVAPIV01_DESFire.h"

#define DEVICE_ADDRESS	(0)

//INS preprocessor
#define SELECT 			(0xA4)
#define READ_BINARY		(0xB0)
#define UPDATE_BINARY	(0xD6)

//crypto
#define AES_MODE (256)
#define KEY_LEN_BYTE AES_MODE/8 

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

bool derive_key(unsigned char *out, const char *pwd, const char *salt, unsigned int iteration)
{
	/*int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
                           unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out);*/
	
	if(PKCS5_PBKDF2_HMAC_SHA1(pwd, strlen(pwd), (const unsigned char *)salt, strlen(salt), iteration, SHA256_DIGEST_LENGTH, out) == 1)return true;
	else return false;
}

bool get_string_from_config(char *value, const char *path)
{
	const char *str_in_config;
	config_t cfg;

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if(! config_read_file(&cfg, "config.cfg"))
	{
		config_destroy(&cfg);
		return false;	//return error
	}

	/* Get pwd. */
	if(config_lookup_string(&cfg, path, &str_in_config))
	{
		memcpy(value, str_in_config, strlen(str_in_config));
		config_destroy(&cfg);
		return true;
	}
	else
	{
		fprintf(stderr, "No mentioned setting in configuration file.\n");
		config_destroy(&cfg);
		return false;
	}
}

char *unbase64(unsigned char *input, int length)
{
	BIO *b64, *bmem;

	char *buffer = (char *)malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);

	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);
	return buffer;
}

bool unwrap_aes_key(unsigned char *out, unsigned char *wrapper_key, unsigned char *key_to_unwrap)
{
	/* unwrap key */
	char unwrp_key_len = 0;
	AES_KEY dec_KEK;
	AES_set_decrypt_key(wrapper_key,256,&dec_KEK);
	unwrp_key_len = AES_unwrap_key(&dec_KEK, 0, out, key_to_unwrap, KEY_LEN_BYTE+8);
	if(unwrp_key_len != KEY_LEN_BYTE)return false;
	else return true;
}

void getTransKey(unsigned char* aes_key, const char* pwd, const char* ACCN, bool printResult)
{
	char wrapped_base64[80];
	memset(wrapped_base64,0,80);
	
	//~ unsigned char aes_key[KEY_LEN_BYTE];
	unsigned char KeyEncryptionKey[KEY_LEN_BYTE];
	int i=0;
	
	/* derive key from pwd + ACCN */
	if(derive_key(KeyEncryptionKey, pwd, ACCN, 10000) == false)
	{
		fprintf(stderr, "error deriving key");
		_exit(5);
	}
	else
	{
		if (printResult)
		{
			printf("derived key: ");
			for(i=0;i<KEY_LEN_BYTE;i++)printf("%.02X ",KeyEncryptionKey[i]);
			printf("\n\n");
		}
	}
	
	if(get_string_from_config(wrapped_base64,"security.transaction")==false)
	{
		fprintf(stderr,"failed to get transaction key from config");
		_exit(5);
	}
	if(printResult)printf("b64 key from config : %s\n\n",wrapped_base64);
	unsigned char *wrapped_unbase64 = (unsigned char *) unbase64((unsigned char *)wrapped_base64, strlen(wrapped_base64)+1);

	if (printResult)
	{
		printf("wrapped unbase64 key: ");
		for(i=0;i<KEY_LEN_BYTE+8;i++)printf("%.02X ",*(wrapped_unbase64+i));
		printf("\n\n");
	}
	
		/* unwrap key using KEK */
	if(unwrap_aes_key(aes_key, KeyEncryptionKey, (unsigned char *)wrapped_unbase64) == false)
	{
		fprintf(stderr,"error unwrapping key");
		_exit(5);
	}
	else
	{
		if (printResult)
		{
			printf("wrapped key: ");
			int i=0;
			for(i=0;i<KEY_LEN_BYTE;i++)printf("%.02X ",aes_key[i]);
			printf("\n\n");
		}
	}
}

bool get_INT64_from_config(long long *value, const char *path)
{
	config_t cfg;

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if(! config_read_file(&cfg, "config.cfg"))
	{
		config_destroy(&cfg);
		return false;	//return error
	}

	/* Get ACCN. */
	if(config_lookup_int64(&cfg, path, (long long int *)value))
	{
		config_destroy(&cfg);
		return true;
	}
	else
	{
		fprintf(stderr, "No mentioned setting in configuration file.\n");
		config_destroy(&cfg);
		return false;
	}
}

bool decrypt_transaction_frame(unsigned char* output, unsigned char* input, unsigned char* IV, unsigned char* aes_key)
{
	/* DO NOT USE IV VALUE AGAIN! 
	 * AFTER DECRYPT USING OpenSSL, IV VALUE CHANGED!! 
	 */

	AES_KEY dec_key;
	AES_set_decrypt_key(aes_key, 256, &dec_key);
	AES_cbc_encrypt(input, output, 32, &dec_key, IV, AES_DECRYPT);
	
	return true;
}

bool verify_data(unsigned char* data, unsigned char* aes_key)
{
	int index = 0;
	index++;
	
	char typeLen = *(data+index);
	index++;
	char payloadLen = *(data+index);
	index++;
	
	// skip type
	index += typeLen;
	
	unsigned char transData[payloadLen];
	memset(transData, 0, payloadLen);
	memcpy(transData, data+index, payloadLen);
	
	if(transData[0]!=55)return false;
	if(transData[1]!=3)return false;
	if(transData[2]!=0)return false;
	
	
	//~ int transSESN = (transData[3]<<8) | transData[4];
	//~ if(transSESN != SESN)_exit(6);
	
	unsigned char ciphertext[32];
	memset(ciphertext, 0, 32);
	memcpy(ciphertext, transData+7, 32);
	
	unsigned char IV[16];
	memset(IV, 0, 16);
	memcpy(IV, transData+39, 16);
	
	unsigned char decryptedPayload[32];
	memset(decryptedPayload,0,32);
	
	if(decrypt_transaction_frame(decryptedPayload, ciphertext, IV, aes_key))
	{
		/* DO NOT USE IV VALUE AGAIN! 
		 * AFTER DECRYPT USING OpenSSL, IV VALUE CHANGED!! 
		 */

		//~ int encryptedSESN = (decryptedPayload[18]<<8)|decryptedPayload[19];
		//~ if(encryptedSESN != transSESN)return false;
		
		int i = 0;
		for(i=0;i<12;i++)
		{
			if(decryptedPayload[20+i] != 12)return false;
		}

		return true;
	}
	else 
	{
		return false;
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
	
	if (argc == 3)valid_arg = true;
	else if ((argc == 2) && (!strcmp(argv[1],"hwid")))
	{
		CV_SetCommunicationType(1);

		int currentAddress = 99;
		int &currentAddressPtr = currentAddress;
		char HWID[16];
		memset(HWID,0,16);
		if(!GetSerialNum(DEVICE_ADDRESS, currentAddressPtr, HWID))
		{
			fprintf(stdout,"DATA:%s\n", HWID);
			return 0;
		}
		else return 1;
	}
	else valid_arg = false;
	
	if (valid_arg == false)
	{
		fprintf(stderr,"Can not start NFC! wrong argument!\n");
		return 5;
	}
	
	//~ int SESN = strtoimax(argv[2],NULL,10);
	//~ printf("SESN: %d\n", SESN);
	
	unsigned char aes_key[32];
	long long ACCN;
	char ACCNstr[32];
	memset(ACCNstr, 0, 32);

	if(get_INT64_from_config(&ACCN, "application.ACCN") == true) 
		sprintf(ACCNstr, "%ju", ACCN);
	else 
	{
		fprintf(stderr, "Failed to get ACCN from config");
		return 5;
	}

	getTransKey(aes_key, argv[1], ACCNstr, false);
	
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

	const unsigned char All_Write_Data[0x05] = {
		0x00,0x03, //NDEF Length
		0xD0,0x00,0x00 //empty NDEF message
	};

	unsigned char RcvdNDEF[270];
	memset(RcvdNDEF, 0, 270);
	
	unsigned char RcvdNDEFLen = 0;

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
	
	unsigned char dataRaw[262];
	memset(dataRaw, 0, 262);
	unsigned char dataRawLen = 0;
	
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
							//0x0005 = Total NDEF length + 2 byte (for NLEN)
							unsigned char ResBuff[4]	= {	0x00,0x05,0x90,0x00 };
							memcpy(TgResponse, ResBuff, 4);
							TgResLen = 4;
						}
						else
						{
							if (Le)
							{
								unsigned char P2;
								P2 = RetData[5];
								memcpy(TgResponse, All_Write_Data+P2, Le);
								
								unsigned char SW1SW2[2] = {0x90,0x00};
								memcpy(TgResponse+Le, SW1SW2, 2);
								TgResLen = Le+2;
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
						
						unsigned char P2 = RetData[5];
						
						if(Lc > 2)
						{
							RcvdNDEFLen = P2+Lc;
							for(i=0;i<Lc;i++)RcvdNDEF[i+P2] = RetData[7+i];
							TgResponse[0] = 0x90;
							TgResponse[1] = 0x00;
							TgResLen = 2;
						}
						else if(Lc == 2)
						{
							dataRawLen = RcvdNDEFLen - 2;
							memcpy(dataRaw, RcvdNDEF+2, dataRawLen);
							if(verify_data(dataRaw, aes_key) == true)
							{
								complete = true;
								TgResponse[0] = 0x90;
								TgResponse[1] = 0x00;
								TgResLen = 2;
							}
							else
							{
								TgResponse[0] = 0x6F;
								TgResponse[1] = 0x00;
								TgResLen = 2;
								fprintf(stdout, "\nDATA: WRONG!\n");
								force_exit = 7;
							}
						}					
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
	
	printf("program exit smoothly\n");
	
	if (complete)
	{
		fprintf(stdout,"DATA:");
		print_data(RcvdNDEF+2, RcvdNDEFLen-2, "Result");
		return 0;
	}
	
	return 2;
}
