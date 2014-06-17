#ifndef UCVAPIV01_DESFireH
#define UCVAPIV01_DESFireH
#include <unistd.h>


/*------define linux version----*/
#ifndef _LINUX_VERSION
#define _LINUX_VERSION
#endif


    #define extern__stdcall extern int

    typedef unsigned char byte;
    typedef unsigned char BYTE;

#ifndef _TOnAutoRead_
#define _TOnAutoRead_
typedef int (*TOnAutoRead)(char *HexDataRead);
#endif


/**************** System Functions ***********************/
extern__stdcall CV_SetCommunicationType(byte aType);//aType 0--COM RS232,1--USB,2--UDP
extern__stdcall CV_GetCommunicationType();//return 0--COM RS232,1--USB,2--UDP
extern__stdcall CV_UDPRun(int SvrPort); //ʼUDPͨ;
extern__stdcall CV_UDPStop();
//extern__stdcall CV_UDPSetCurrentSvrPort(int SvrPort);
extern__stdcall CV_SetRemoteIPPort(unsigned char *ip,int port);  //ԶIPַ

//32. Get the current API commuication version.
extern__stdcall GetVersionAPI(char *VersionAPI);

//1. Set communciation baudrate.                  
extern__stdcall SetRS232BytesTimeOut(unsigned long iTO);
extern__stdcall OpenComm(char *com,int Baudrate);


//1.1 simultaneity create multi-comm ports;
//  : ֣    
//ʱ  : 2005-08-16
extern__stdcall CreateCommPort(int SerialNUM,unsigned char *CommID,int Baudrate );

//2. To close communication port.
extern__stdcall CloseComm(void);

//3. Set device(firmware) address for RS485 communication.
extern__stdcall SetDeviceAddress(int DeviceAddress,unsigned char &newAddress,unsigned char mode,unsigned char *buffer);

//4. Get device(firmware) address and serial number from target device.
extern__stdcall GetSerialNum(int DeviceAddress,int &CurrentAddress, char *SerialNum);

//5. Set the device(firmware) serial number.
extern__stdcall SetSerialNum(int DeviceAddress,char *SerialNum);

//6. Get device(firmware) version number.
extern__stdcall GetVersionNum(int DeviceAddress,char *VersionNum);



//xx Get user information
extern__stdcall GetUserInfo(int DeviceAddress, char *user_info);

//xx Set the device(firmware) serial number.
extern__stdcall SetUserInfo(int DeviceAddress,char *user_info);

// Enable/Disable Auto Power Save
extern__stdcall SetAutoPowerSave(int DeviceAddress, unsigned char flg_save);

// Set firmware communication baudrate
extern__stdcall SetFirmwareBaudrate(int DeviceAddress,unsigned char Baudrate);

/**************** I/O Functions ***********************/
//------IO Functions
//7. To trigger IO port
//8. Set output port to active forever.
extern__stdcall SetExtPort(int DeviceAddress,unsigned char Ports);
//10. Get port status.
extern__stdcall GetPort(int DeviceAddress,unsigned char *status);

//11. Toggle LED ON OFF .
extern__stdcall ActiveLED(int DeviceAddress,unsigned char NumLED,unsigned char time,unsigned char cycle);

//12. To ON LED forever.
extern__stdcall SetLED(int DeviceAddress,unsigned char NumLED);

//14. To control buzzer ON/OFF or ON OFF ON OFF
extern__stdcall ActiveBuzzer(int DeviceAddress,unsigned char mode,unsigned char *buffer);

 //25. Reset RF field.
extern__stdcall RF_Field(int DeviceAddress,unsigned char mode);

/**************** ISO14443 Functions ***********************/
// The following Function prototypes are used for MIFARE - Va 01/08/2001
extern__stdcall MF_Request(int DeviceAddress, unsigned char inf_mode, unsigned char *buffer);

//16. During the anticollision loop.
extern__stdcall MF_Anticoll(int DeviceAddress,unsigned char *snr,unsigned char &status);
extern__stdcall MF_Anticoll2(int DeviceAddress,unsigned char *snr,unsigned char &status);
extern__stdcall MF_UL_Anticoll2(int DeviceAddress,unsigned char *snr,unsigned char &status);
extern__stdcall MF_Anticoll3(int DeviceAddress,unsigned char *snr,unsigned char &status);
//17. Select one tag for further communication.
extern__stdcall MF_Select(int DeviceAddress,unsigned char *snr);
extern__stdcall MF_Select2(int DeviceAddress,unsigned char *snr);
extern__stdcall MF_Select3(int DeviceAddress,unsigned char *snr);

//xx To place tag in halt state thus no more responding
extern__stdcall MF_Halt(int DeviceAddress,unsigned char mode);

extern__stdcall MF_ReaderHalt(int DeviceAddress,unsigned char mode);
//29. Send the generic command to tag.
extern__stdcall SLE_Generic(int DeviceAddress,unsigned char CRC_Flag,unsigned char &length,unsigned char *buffer);
extern__stdcall SLE_GenericEx(int DeviceAddress,unsigned char CRC_Flag,unsigned char TimeOut,unsigned char &length,unsigned char *buffer);  



/**************** MIFARE Functions ***********************/
//xx MIFARE Authentication
extern__stdcall MF_Auth(int DeviceAddress,unsigned char mode, unsigned char *snr, unsigned char block);

// xx Mifare Read
extern__stdcall MF_Read(int DeviceAddress,unsigned char add_blk, unsigned char num_blk, unsigned char *buffer);

//xx Mifare Write
extern__stdcall MF_Write(int DeviceAddress,unsigned char add_blk, unsigned char num_blk, unsigned char *buffer);

extern__stdcall MF_UL_AnticollL1(int DeviceAddress,unsigned char *UID_Part1,unsigned char *BCC1);
extern__stdcall MF_UL_SelectL1(  int DeviceAddress,unsigned char *UID_Part1,unsigned char  BCC1);  
extern__stdcall MF_UL_AnticollL2(int DeviceAddress,unsigned char *UID_Part2,unsigned char *BCC2);
extern__stdcall MF_UL_SelectL2(  int DeviceAddress,unsigned char *UID_Part2,unsigned char  BCC2);
extern__stdcall MF_UL_Read(int DeviceAddress,int StartPage , unsigned char *FromData_16Bytes);
extern__stdcall MF_UL_Write(int DeviceAddress,int PageNum , unsigned char *ToData_4Bytes);



//xx MIFARE Increment function
extern__stdcall MF_Increment(int DeviceAddress,unsigned char add_blk, int value);

//xx MIFARE Decrement function
extern__stdcall MF_Decrement(int DeviceAddress,unsigned char add_blk, int value);

//xx MIFARE Transfer function
extern__stdcall MF_Transfer(int DeviceAddress,unsigned char add_blk);

//xx MIFARE Restore function
extern__stdcall MF_Restore(int DeviceAddress,unsigned char add_blk);

// xx MIFARE Write Value function
extern__stdcall MF_InitValue(int DeviceAddress,unsigned char add_blk, int value);

//xx MIFARE Read Value function
extern__stdcall MF_ReadValue(int DeviceAddress,unsigned char add_blk, int *value);

//xx Mifare direct load key to Master Key Buffer
extern__stdcall MF_LoadKey(int DeviceAddress,unsigned char *key);

//xx Mifare store Master key to EEPROM
extern__stdcall MF_StoreKeyToEE(int DeviceAddress,unsigned char Key_type,unsigned char Sector,unsigned char *Key);

//xx Mifare load Master key from EEPROM
extern__stdcall MF_LoadKeyFromEE(int DeviceAddress,unsigned char Key_type,unsigned char Sector);

/**************** ISO14443 Type B Functions ***********************/


// Generic TypeB command
extern__stdcall Generic_B(int DeviceAddress,unsigned char &length,unsigned char *buffer);
                                 
extern__stdcall Generic_BEx(int DeviceAddress,unsigned char CRC_Flag,unsigned char TimeOut,
						   unsigned char &length,unsigned char *buffer);


/**************** MIFARE Functions ***********************/
extern__stdcall MF_HLRead(int DeviceAddress,unsigned char mode,
																			unsigned char blk_add,unsigned char num_blk,
                                                         unsigned char *snr, unsigned char *buffer);

                                                         //Mifare High Level Read
extern__stdcall MF_HLWrite(int DeviceAddress,unsigned char mode,
																			unsigned char blk_add,unsigned char num_blk,
                                                         unsigned char *snr, unsigned char *buffer);

extern__stdcall MF_HLInitVal(int DeviceAddress,unsigned char mode,unsigned char SectNum,
                                                         unsigned char *snr, int value);

extern__stdcall MF_HLDec(int DeviceAddress,unsigned char mode,unsigned char SectNum,
                                                         unsigned char *snr, int *value);

extern__stdcall MF_HLInc(int DeviceAddress,unsigned char mode,unsigned char SectNum,
                                                         unsigned char *snr, int *value);


extern__stdcall MF_HLRequest(int DeviceAddress, unsigned char mode, int &len, unsigned char *snr);

/**************** Misc Functions ***********************/

//------------------------------------------------------------------------------
//Below routine used for internal debug
//------------------------------------------------------------------------------

//xx Read Write xdata direct to read or write firmware I/O address for debug 13/08/01 - John
extern__stdcall ReadWriteXdata(int DeviceAddress,unsigned char mode,int regAddress,unsigned char &value);

//The ReadChar routine for read one char from com port
extern__stdcall ReadChar(unsigned char *byte);

//..ReadCharsമڷʿ
//..  : ֣    
//..ʱ  : 2005-08-16
extern__stdcall ReadChars(int DeviceAddress,unsigned char *byte);
extern__stdcall GenericCMD(int DeviceAddress,unsigned char mode, unsigned char *buffer, int &NumByte);
extern__stdcall SetWiegandStatus(int DeviceAddress,unsigned char status); 
extern__stdcall GetWiegandMode(int DeviceAddress,unsigned char *reqbuffer);
extern__stdcall ActiveWiegandMode(int DeviceAddress,unsigned char status);
extern__stdcall WiegandMode(int DeviceAddress,unsigned char *data);
extern__stdcall LcdDisplayLogo(int DeviceAddress,unsigned char*data);
extern__stdcall LcdDisplay(int DeviceAddress,unsigned char address,unsigned char length, char *Dstring);
extern__stdcall GetKey(int DeviceAddress,unsigned char *keybuffer);

/*		ISO15693     */

extern__stdcall  CMD_ISO15693_Inventory(int DeviceAddress,unsigned char flags,unsigned char AFI,unsigned char masklengh ,unsigned char *maskvalue,unsigned char*databuffer);
extern__stdcall  CMD_ISO15693_Stay_Quiet(int DeviceAddress,unsigned char flags,unsigned char*UID);
extern__stdcall  CMD_ISO15693_Read(int DeviceAddress,unsigned char flags,unsigned char Firstblock, unsigned char Number,unsigned char*UID,unsigned char*databuffer);
extern__stdcall  CMD_ISO15693_Write(int DeviceAddress,unsigned char flags,unsigned char Firstblock,unsigned char Number,unsigned char*UID,unsigned char*databuffer);
extern__stdcall  CMD_ISO15693_Lock_Block(int DeviceAddress,unsigned char flags,unsigned char block,unsigned char*UID);
extern__stdcall  CMD_ISO15693_Select(int DeviceAddress,unsigned char flags,unsigned char*UID);
extern__stdcall  CMD_ISO15693_Reset_To_Ready(int DeviceAddress,unsigned char flags,unsigned char*UID);
extern__stdcall  CMD_ISO15693_Write_AFI(int DeviceAddress,unsigned char flags, unsigned char AFI, unsigned char*UID);
extern__stdcall  CMD_ISO15693_Lock_AFI(int DeviceAddress,unsigned char flags,unsigned char*UID);
extern__stdcall  CMD_ISO15693_Write_DSFID(int DeviceAddress,unsigned char flags,unsigned char DSFID,unsigned char*UID);
extern__stdcall  CMD_ISO15693_Lock_DSFID(int DeviceAddress,unsigned char flags,unsigned char*UID);
extern__stdcall  CMD_ISO15693_GET_System_Information(int DeviceAddress,unsigned char flags,unsigned char*UID,unsigned char *databuffer);
extern__stdcall  CMD_ISO15693_GetMultipleBlockSecurity(int DeviceAddress,unsigned char flags,unsigned char Firstblock,unsigned char Number,unsigned char*UID,unsigned char*databuffer);
extern__stdcall  CMD_ISO15693_Generic(int DeviceAddress,unsigned char length,unsigned char *databuffer);
extern__stdcall  CMD_ISO15693_Inventory16(int DeviceAddress,unsigned char Flags,unsigned char AFI,int *CardNum,unsigned char*DataBuffer);

/* My-d */
extern__stdcall  CMD_Myd_write(int DeviceAddress,unsigned char flags,unsigned char block,unsigned char*UID,unsigned char*databuffer);
extern__stdcall  CMD_Myd_read(int DeviceAddress,unsigned char flags,unsigned char block,unsigned char*UID,unsigned char*databuffer);

/*Խӿ*/
extern__stdcall  WriteCommandCode(int *ByteLen,unsigned char *DataBuffer);
extern__stdcall  ReadCommandCode(int *ByteLen,unsigned char *DataBuffer);
extern__stdcall  ReaderC_EXT(int DeviceAddress,byte iTime);
extern__stdcall  ReaderReset(int DeviceAddress);  
extern__stdcall  ReadOriginalData(unsigned long iTimeOut,unsigned long iReadLength,
								  unsigned char *pDataBur,unsigned long *iSuccessLen);


/**************** DESFire EV1 Commands execute ad Firmware***********************/
extern__stdcall  RATS(int DeviceAddress,unsigned char CID,unsigned char FSDI,unsigned char *ATS,unsigned int *ATSLen);

extern__stdcall  PPS(int DeviceAddress,unsigned char CID, unsigned char DSI, unsigned char DRI);
extern__stdcall  DESELECT(int DeviceAddress,unsigned char CID);
extern__stdcall  MF_DFEV1_Authenticate(int DeviceAddress,unsigned char CID,unsigned char CryptoType,
								  unsigned char KeyNo, unsigned char *Key);
extern__stdcall  MF_DFEV1_ChangeKeySettings(int DeviceAddress,unsigned char CID,unsigned char MasterKeySettings);
extern__stdcall  MF_DFEV1_GetKeySettings(int DeviceAddress,unsigned char CID,unsigned char *MasterKeySettings,unsigned char *KeyNumber,unsigned char *CryptoType);
extern__stdcall  MF_DFEV1_ChangeKey(int DeviceAddress,unsigned char CID,unsigned char KeyNo, unsigned char CryptoType,
							   unsigned char KeyVersion, unsigned char *NewKey, unsigned char *OldKey);
extern__stdcall  MF_DFEV1_GetKeyVersion(int DeviceAddress,unsigned char CID, unsigned char KeyNo,unsigned char *KeyVersion);
extern__stdcall  MF_DFEV1_CreateApplication(int DeviceAddress,unsigned char CID, int AID,
						                    unsigned char MasterKeySettings, unsigned char KeyNum, unsigned char CryptoType);
extern__stdcall  MF_DFEV1_DeleteApplication(int DeviceAddress,unsigned char CID, int AID);
extern__stdcall  MF_DFEV1_GetApplicationIDs(int DeviceAddress,unsigned char CID, int *AIDs, int *AIDNum);
extern__stdcall  MF_DFEV1_SelectApplication(int DeviceAddress,unsigned char CID, int AID);
extern__stdcall  MF_DFEV1_FormatPICC(int DeviceAddress,unsigned char CID);
extern__stdcall  MF_DFEV1_GetVersion(int DeviceAddress,unsigned char CID, unsigned char *VersionInfo,unsigned int *VersionInfoLen);
extern__stdcall  MF_DFEV1_GetFreeMem(int DeviceAddress,unsigned char CID, int *RemainMemSize);
extern__stdcall  MF_DFEV1_GetCardUID(int DeviceAddress,unsigned char CID, unsigned char *UID,unsigned int *UIDLen);
extern__stdcall  MF_DFEV1_SetConfiguration(int DeviceAddress,unsigned char CID, unsigned char ConfigType, unsigned char *ConfigData,unsigned int ConfigDataLen);
extern__stdcall  MF_DFEV1_GetFileIDs(int DeviceAddress,unsigned char CID, unsigned char *FileIDs,unsigned int *FileIDsLen);
extern__stdcall  MF_DFEV1_GetFileSettings(int DeviceAddress,unsigned char CID,unsigned char FileID, unsigned char *FileSettings);
extern__stdcall  MF_DFEV1_ChangeFileSettings(int DeviceAddress,unsigned char CID,unsigned char FileID,unsigned char CmtSet,unsigned short AccessRights,bool Is_Rights_Free);
extern__stdcall  MF_DFEV1_CreateDataFile(int DeviceAddress,unsigned char CID,unsigned char FileID,unsigned char FileType,
									unsigned char CmtSet,unsigned short AccRights,unsigned int CreateSize);
extern__stdcall  MF_DFEV1_CreateValueFile(int DeviceAddress,unsigned char CID,unsigned char FileID,unsigned char CmtSet,
									unsigned short AccRights,unsigned int LLimit,unsigned int ULimit,unsigned int InitVal,unsigned char LimitCredit);
extern__stdcall  MF_DFEV1_CreateRecordFile(int DeviceAddress,unsigned char CID,unsigned char FileID,unsigned char FileType,unsigned char CmtSet,
									unsigned short AccRights,unsigned int SingleRecordSize,unsigned int RecordNumber);
extern__stdcall  MF_DFEV1_DeleteFile(int DeviceAddress,unsigned char CID, unsigned char FileID);
extern__stdcall  MF_DFEV1_ReadData(int DeviceAddress,unsigned char CID,unsigned char FileID,unsigned char CmtSet,
									unsigned int Offset,unsigned int ReadLength,unsigned char *ReturnData,unsigned int *ReturnDataLen);
extern__stdcall  MF_DFEV1_WriteData(int DeviceAddress,unsigned char CID,unsigned char FileID,unsigned char CmtSet,
									unsigned int Offset,unsigned int WriteDataLength,unsigned char *WriteData);
extern__stdcall  MF_DFEV1_GetValue(int DeviceAddress,unsigned char CID, unsigned char FileID, unsigned char CmtSet, int *RetValue);
extern__stdcall  MF_DFEV1_Credit(int DeviceAddress,unsigned char CID, unsigned char FileID, unsigned char CmtSet,unsigned int IncValue);
extern__stdcall  MF_DFEV1_LimitedCredit(int DeviceAddress,unsigned char CID, unsigned char FileID, unsigned char CmtSet,unsigned int IncValue);
extern__stdcall  MF_DFEV1_Debit(int DeviceAddress,unsigned char CID, unsigned char FileID, unsigned char CmtSet,unsigned int DecValue);
extern__stdcall  MF_DFEV1_WriteRecord(int DeviceAddress,unsigned char CID,unsigned char FileID,unsigned char CmtSet,
									unsigned int Offset,unsigned int RecordLength,unsigned char *RecordData);
extern__stdcall  MF_DFEV1_ReadRecord(int DeviceAddress,unsigned char CID,unsigned char FileID,unsigned char CmtSet,
									unsigned int Offset,unsigned int ReadNumber,unsigned int RecSize,unsigned char *ReturnData,unsigned int *ReturnDataLen);
extern__stdcall  MF_DFEV1_ClearRecordFile(int DeviceAddress,unsigned char CID,unsigned char FileID);
extern__stdcall  MF_DFEV1_CommitTransaction(int DeviceAddress,unsigned char CID);
extern__stdcall  MF_DFEV1_AbortTransaction(int DeviceAddress,unsigned char CID); 
extern__stdcall MF_DFEV1_KeySetting(int DeviceAddress,unsigned char KeyNo,unsigned char CryptoType,unsigned char *Key);
extern__stdcall MF_DFEV1_FileSetting(int DeviceAddress,int AID,unsigned char KeyNo,unsigned char FileID,unsigned char FileType,
									unsigned char CmtSet,unsigned int Offset,unsigned int Length,unsigned int RecSize);  
extern__stdcall  MF_DFEV1HL_Read(int DeviceAddress,unsigned char CID,int AID,unsigned char KeyNo,
								 unsigned char FileID,unsigned char FileType,unsigned char CmtSet,unsigned int Offset,unsigned int Length,
								 unsigned int RecSize,unsigned char *Data,unsigned int *ReadLen);
extern__stdcall  MF_DFEV1HL_Write(int DeviceAddress,unsigned char CID,int AID,unsigned char KeyNo,
								 unsigned char FileID,unsigned char FileType,unsigned char CmtSet,unsigned int Offset,unsigned int Length,
								 unsigned char *Data);
extern__stdcall  MF_DFEV1HL_ClearReads(int DeviceAddress,unsigned char CID,int AID,unsigned char KeyNo, unsigned char FileID);
extern__stdcall  MF_DFEV1HL_GetValue(int DeviceAddress,unsigned char CID,int AID,unsigned char KeyNo, unsigned char FileID,unsigned char CmtSet, int *RetValue);
extern__stdcall  MF_DFEV1HL_Credit(int DeviceAddress,unsigned char CID,int AID,unsigned char KeyNo, unsigned char FileID,unsigned char CmtSet, unsigned int IncValue,bool IsLimited=false);
extern__stdcall  MF_DFEV1HL_Debit(int DeviceAddress,unsigned char CID, int AID,unsigned char KeyNo, unsigned char FileID,unsigned char CmtSet, unsigned int DecValue);


		//Mifare Plus ommands execute at firmware
extern__stdcall MF_Plus_WritePerso(int DeviceAddress,unsigned char CID,unsigned short BNr,unsigned char *Data);
extern__stdcall MF_Plus_CommitPerso(int DeviceAddress,unsigned char CID);
		//Mifare Plus SL1 commands execute at firmware
extern__stdcall MF_Plus_SL1AESAuth(int DeviceAddress,unsigned char *AESKey);
		//Mifare Plus SL2 commands execute at firmware
extern__stdcall MF_Plus_SL2AESAuth(int DeviceAddress,unsigned short BNr,unsigned char *AESKey,unsigned char *MFKey,unsigned char *MFSessionKey);
		//Mifare Plus SL3 commands execute at firmware
extern__stdcall MF_Plus_FirstAuth(int DeviceAddress,unsigned char CID,unsigned short BNr,unsigned char *AESKey);
extern__stdcall MF_Plus_FollowAuth(int DeviceAddress,unsigned char CID,bool IsPlusX,unsigned short BNr,unsigned char *AESKey);
extern__stdcall MF_Plus_SL3ResetAuth(int DeviceAddress,unsigned char CID);
extern__stdcall MF_Plus_SL3Read(int DeviceAddress,unsigned char CID,bool IsPlusX,unsigned short BNr,unsigned char BlockNum,
							bool MACC,bool Plaintext,bool MACR,unsigned char *DataRead,unsigned char *DataReadLen);
extern__stdcall MF_Plus_SL3Write(int DeviceAddress,unsigned char CID,bool IsPlusX,unsigned short BNr,
							 bool Plaintext,bool MACR,unsigned char *DataToWrite);
extern__stdcall MF_Plus_SL3Value(int DeviceAddress,unsigned char CID,unsigned char OPType,unsigned short BNr,bool MACR,int *Value);
extern__stdcall MF_Plus_AutoReadSetting(int DeviceAddress,unsigned char *Setting);
extern__stdcall MF_Plus_GetAutoReadSetting(int DeviceAddress,unsigned char *Setting);


//**************Mifare Plus Commands execute at SDK******************/
extern__stdcall MF_PS_AnticollL1(int DeviceAddress,unsigned char *UID_Part1,unsigned char *BCC1);
extern__stdcall MF_PS_SelectL1(int DeviceAddress,unsigned char *UID_Part1,unsigned char BCC1);
extern__stdcall MF_PS_AnticollL2(int DeviceAddress,unsigned char *UID_Part2,unsigned char *BCC2);
extern__stdcall MF_PS_SelectL2(int DeviceAddress,unsigned char *UID_Part2,unsigned char BCC2);
extern__stdcall MF_PS_RATSEx(int DeviceAddress,unsigned char CID,unsigned char FSDI=5,unsigned char *ATS=NULL); 
extern__stdcall MF_PS_PPS(int DeviceAddress,unsigned char CID,unsigned char DSI=0,unsigned char DRI=0 );
extern__stdcall MF_PS_DESELECTEx(int DeviceAddress,unsigned char CID);
extern__stdcall MF_PS_WritePerso(int DeviceAddress,unsigned char CID,unsigned short BNr,unsigned char *Data);
extern__stdcall MF_PS_CommitPerso(int DeviceAddress,unsigned char CID);     
extern__stdcall MF_PS_SL1AESAuth(int DeviceAddress,unsigned char *AESKey);
extern__stdcall MF_PS_SL2AESAuth(int DeviceAddress,unsigned short BNr,unsigned char *AESKey,unsigned char *MFKey,unsigned char *MFSessionKey);
extern__stdcall MF_PS_FirstAuth(int DeviceAddress,unsigned char CID,unsigned short BNr,unsigned char *AESKey);
extern__stdcall MF_PS_FollowAuth(int DeviceAddress,unsigned char CID,bool IsPlusX,unsigned short BNr,unsigned char *AESKey);
extern__stdcall MF_PS_SL3ResetAuth(int DeviceAddress,unsigned char CID);
extern__stdcall MF_PS_SL3Read(int DeviceAddress,unsigned char CID,bool IsPlusX,unsigned short BNr,unsigned char BlockNum,
							  bool MACC,bool Plaintext,bool MACR,unsigned char *DataRead,unsigned char *DataReadLen);
extern__stdcall MF_PS_SL3Write(int DeviceAddress,unsigned char CID,bool IsPlusX,unsigned short BNr,
							   bool Plaintext,bool MACR,unsigned char *DataToWrite);
extern__stdcall MF_PS_SL3Value(int DeviceAddress,unsigned char CID,unsigned char OPType,unsigned short BNr,bool MACR,int *Value);

extern__stdcall  SetOnAutoRead(TOnAutoRead aEventFun);
extern__stdcall  AutoRead_Run();
extern__stdcall  AutoRead_Stop();
extern__stdcall  IsAutoRead();
/****************end  DESFire EV1 Commands ***********************/

/****************start PN532 Commands implemented at SDK ***********************/
extern__stdcall SetNFCState(int DeviceAddress,unsigned char State);
extern__stdcall PN532_GetFirmwareVersion(int DeviceAddress,unsigned char *IC,unsigned char *FVer,unsigned char *FRev,unsigned char *Support);
extern__stdcall PN532_GetGeneralStatus(int DeviceAddress,unsigned char *GeneralStatus,unsigned char *GeneralStatusLen);
extern__stdcall PN532_SAMConfiguration(int DeviceAddress,unsigned char Mode,unsigned char Timeout,unsigned char IRQ=1); 
extern__stdcall PN532_RFConfiguration(int DeviceAddress,unsigned char CfgItem,unsigned char *ConfigurationData); 
extern__stdcall PN532_SetParameters(int DeviceAddress,unsigned char Flags);
extern__stdcall PN532_InJumpForDEP(int DeviceAddress,unsigned char ActPass,unsigned char BR,
									unsigned char *ActPassData,
									unsigned char ActPassDataLen,
									unsigned char *NFCID3,
									unsigned char NFCID3Len,
									unsigned char *G,
									unsigned char GLen,
									unsigned char *RData,
									unsigned char *RDataLen);
extern__stdcall PN532_InJumpForPSL(int DeviceAddress,unsigned char ActPass,unsigned char BR,
									unsigned char *ActPassData,
									unsigned char ActPassDataLen,
									unsigned char *NFCID3,
									unsigned char NFCID3Len,
									unsigned char *G,
									unsigned char GLen,
									unsigned char *RData, unsigned char *RDataLen);
extern__stdcall PN532_InDataExchange(int DeviceAddress,unsigned char Tg,
									 unsigned char *SData,unsigned char SDataLen,
									 unsigned char *RData,unsigned char *RDataLen);  
extern__stdcall PN532_InListPassiveTarget(int DeviceAddress,unsigned char MaxTg,unsigned char BrTy,
										  unsigned char *InitiatorData,unsigned char InitiatorDataLen,
										  unsigned char *NbTg,unsigned char *TargetData,unsigned char *TargetDataLen);
extern__stdcall PN532_InSelect(int DeviceAddress,unsigned char Tg);
extern__stdcall PN532_InDeselect(int DeviceAddress,unsigned char Tg);
extern__stdcall PN532_InRelease(int DeviceAddress,unsigned char Tg);
extern__stdcall PN532_TgInitAsTarget(int DeviceAddress,unsigned char *Mode,unsigned char *MifareParams,unsigned char *FeliCaParams,
									 unsigned char *NFCID3,unsigned char GtLen,unsigned char *Gt,unsigned char TkLen,unsigned char *Tk,
									 unsigned char *InitCMD,unsigned char *InitCMDLen);
extern__stdcall PN532_TgGetData(int DeviceAddress,unsigned char *RData,unsigned char *RDataLen);
extern__stdcall PN532_TgSetData(int DeviceAddress,unsigned char *SData,unsigned char SDataLen);

extern__stdcall SLE_Generic_PN532(int DeviceAddress,unsigned char *length,unsigned char *buffer);
extern__stdcall SLE_Generic_SAM(int DeviceAddress,unsigned char *length,unsigned char *buffer);
extern__stdcall PN_InListPassiveTarget(int DeviceAddress,unsigned char CardType,unsigned char MaxTg,unsigned char BaudRate,unsigned char IniDataLen,
								   unsigned char *IniData,unsigned char *NbTg,unsigned char *RDataLen,unsigned char *RData);
extern__stdcall PN_SelectTarget(int DeviceAddress,unsigned char TargetNum);
extern__stdcall PN_ExchangeData(int DeviceAddress,unsigned char InTg,unsigned char BaudRate,unsigned char TimeOut,
							  unsigned char *NFCID3,unsigned char *Data,unsigned char *DataLen);
/****************end  PN532 Commands implemented at SDK ***********************/
extern__stdcall ISO7816_ATR( int DeviceAddress, unsigned char ucCardSlot,
					unsigned char* ATR, int& nATR_Len, int nATR_MaxLen, int CNReaderType=1);
extern__stdcall ISO7816_APDU_Exchange(
					int DeviceAddress, unsigned char ucCardSlot,
					unsigned char* DataToCard, int nBytes_DataToCard,
					unsigned char* DataFromCard, int& nBytes_DataFromCard,
					int nMaxBytes_DataFromCard, int CNReaderType=1);
/****************end  PN532 Commands implemented at SDK ***********************/

/**************************start NFC command *********************************/
extern__stdcall NFC_LLCP_Symm(int DeviceAddress, unsigned char* RetData);
extern__stdcall NFC_LLCP_Connect(int DeviceAddress, unsigned char DSAP, unsigned char SSAP, unsigned char* MIUX, unsigned char RW, unsigned char* SN, unsigned char* RetData);
extern__stdcall NFC_LLCP_Cc(int DeviceAddress, unsigned char DSAP, unsigned char SSAP, unsigned char* MIUX, unsigned char RW, unsigned char* RetData);
extern__stdcall NFC_LLCP_Disc(int DeviceAddress, unsigned char DSAP, unsigned char SSAP, unsigned char* RetData);
extern__stdcall NFC_LLCP_I(int DeviceAddress, unsigned char DSAP, unsigned char SSAP, unsigned char SEQ, unsigned char* Data, unsigned char DataLen, unsigned char* RetData);
extern__stdcall NFC_LLCP_Rr(int DeviceAddress, unsigned char DSAP, unsigned char SSAP, unsigned char SEQ, unsigned char* RetData);
extern__stdcall NFC_LLCP_Rnr(int DeviceAddress, unsigned char DSAP, unsigned char SSAP, unsigned char SEQ, unsigned char* RetData);
extern__stdcall NFC_LLCP_Dm(int DeviceAddress, unsigned char DSAP, unsigned char SSAP, unsigned char RESON, unsigned char* RetData);
extern__stdcall NFC_LLCP_Frmr(int DeviceAddress, unsigned char DSAP, unsigned char SSAP, unsigned char* INFO, unsigned char* RetData);
extern__stdcall NFC_LLCP_Ui(int DeviceAddress, unsigned char DSAP, unsigned char SSAP, unsigned char* Data, unsigned char* RetData);
extern__stdcall NFC_LLCP_Sdreq(int DeviceAddress, unsigned char DSAP, unsigned char SSAP, unsigned char TID, unsigned char* SN_URI, unsigned char* RetData);
extern__stdcall NFC_LLCP_Sdres(int DeviceAddress, unsigned char DSAP, unsigned char SSAP, unsigned char TID, unsigned char SAP, unsigned char* RetData);
extern__stdcall NFC_LLCP_Poll(int DeviceAddress, unsigned char* RetData);

extern__stdcall NFC_T4TA_Select(int DeviceAddress, unsigned char P1, unsigned char P2, unsigned char length, unsigned char* data, unsigned char* RetData);
extern__stdcall NFC_T4TA_Read(int DeviceAddress, unsigned char P1, unsigned char P2, unsigned char length, unsigned char* RetData);
extern__stdcall NFC_T4TA_Write(int DeviceAddress, unsigned char P1, unsigned char P2, unsigned char length, unsigned char* data, unsigned char* RetData);

extern__stdcall NFC_T1T_Rall(int DeviceAddress, unsigned char* uid, unsigned char* RetData);
extern__stdcall NFC_T1T_Read(int DeviceAddress, unsigned char add, unsigned char* uid, unsigned char* RetData);
extern__stdcall NFC_T1T_Write_E(int DeviceAddress, unsigned char add, unsigned char data, unsigned char* uid, unsigned char* RetData);
extern__stdcall NFC_T1T_Write_Ne(int DeviceAddress, unsigned char add, unsigned char data,  unsigned char* uid, unsigned char* RetData);
extern__stdcall NFC_T1T_Rseg(int DeviceAddress, unsigned char add, unsigned char* uid, unsigned char* RetData);
extern__stdcall NFC_T1T_Read8(int DeviceAddress, unsigned char add, unsigned char* uid, unsigned char* RetData);
extern__stdcall NFC_T1T_Write_E8(int DeviceAddress, unsigned char add, unsigned char* data, unsigned char* uid, unsigned char* RetData);
extern__stdcall NFC_T1T_Write_Ne8(int DeviceAddress, unsigned char add, unsigned char* data, unsigned char* uid, unsigned char* RetData);

extern__stdcall NFC_T3T_Check(int DeviceAddress, unsigned char* uid, unsigned char svc, unsigned char* sc, unsigned char blk, unsigned char flag2, unsigned char* bl, unsigned char* RetData);
extern__stdcall NFC_T3T_Update(int DeviceAddress, unsigned char* uid, unsigned char svc, unsigned char* sc, unsigned char blk, unsigned char flag2, unsigned char* bl, unsigned char* data, unsigned char* RetData);

extern__stdcall NFC_Target(int DeviceAddress, unsigned char* RetData);

extern__stdcall NFC_Picc_Init(int DeviceAddress, unsigned char Mode, unsigned char* MParam,
								unsigned char* FParam, unsigned char* NFCID3t, unsigned char GtLen,
								unsigned char* Gt, unsigned char TkLen, unsigned char* Tk, unsigned char* RetData);
extern__stdcall NFC_Picc_Command(int DeviceAddress, unsigned char* RetData);
extern__stdcall NFC_Picc_Response(int DeviceAddress, unsigned char TgResLen, unsigned char* TgResponse, unsigned char* RetData);

/**************************end NFC command *********************************/

extern__stdcall SetUSBNum(int USBNum);

extern__stdcall MF_UL_C_Auth(int DeviceAddress, unsigned char *Key);
/**************************begin SRI command******************************/
extern__stdcall ISO7816_APDU_Exchange_T1(
					int DeviceAddress, unsigned char ucCardSlot,
					unsigned char* DataToCard, int nBytes_DataToCard,
					unsigned char* DataFromCard, int& nBytes_DataFromCard,
					int nMaxBytes_DataFromCard);
extern__stdcall ISO7816_T1ByPass(int DeviceAddress, int Slot, int SendDataLen, unsigned char *SendData, unsigned char *RetData, int &RetDataLen);
extern__stdcall ISO7816_PPS(int DeviceAddress, int Slot, unsigned char *PPS, unsigned char *RetData, int &RetDataLen);
extern__stdcall SRI_Poll(int DeviceAddress, int &CIDLen, unsigned char *CID);
extern__stdcall SRI_Select(int DeviceAddress, int CID);
extern__stdcall SRI_Get_UID(int DeviceAddress, unsigned char *UID);
extern__stdcall SRI_Read(int DeviceAddress, int BLK, unsigned char *Data);
extern__stdcall SRI_Write(int DeviceAddress, int BLK, unsigned char *Data);
extern__stdcall SRI_Release(int DeviceAddress);
/**************************end SRI command  ******************************/

extern__stdcall DefaultSetting(int DeviceAddress, int *NewDeviceAddress, int *baudrate, unsigned char *WiegandFormate);

//******************ISO7816 (JCOP2.2智能卡预个人化操作指令)***********************************
extern__stdcall ISO7816_SelectRoot(int DeviceAddress, unsigned char Slot, unsigned char *Key, unsigned char *RetData);
extern__stdcall ISO7816_BOOT(int DeviceAddress, unsigned char Slot, unsigned char *RetData);
extern__stdcall ISO7816_Key1(int DeviceAddress, unsigned char Slot, unsigned char *Key, unsigned char *RetData);
extern__stdcall ISO7816_Key2(int DeviceAddress, unsigned char Slot, unsigned char *Key, unsigned char *RetData);
extern__stdcall ISO7816_Key3(int DeviceAddress, unsigned char Slot, unsigned char *Key, unsigned char *RetData);
extern__stdcall ISO7816_Key1Version(int DeviceAddress, unsigned char Slot, unsigned char Version, unsigned char *RetData);
extern__stdcall ISO7816_Key2Version(int DeviceAddress, unsigned char Slot, unsigned char Version, unsigned char *RetData);
extern__stdcall ISO7816_Key3Version(int DeviceAddress, unsigned char Slot, unsigned char Version, unsigned char *RetData);
extern__stdcall ISO7816_Protect(int DeviceAddress, unsigned char Slot, unsigned char *RetData);
extern__stdcall ISO7816_FUSE(int DeviceAddress, unsigned char Slot, unsigned char *RetData);
extern__stdcall ISO7816_Identify(int DeviceAddress, unsigned char Slot, unsigned char *RetDataLen, unsigned char *RetData);
extern__stdcall ISO7816_ReadData(int DeviceAddress, unsigned char Slot, unsigned char DataLen, unsigned char *Address, unsigned char *RetDataLen, unsigned char *RetData);
extern__stdcall ISO7816_WriteData(int DeviceAddress, unsigned char Slot, unsigned char DataLen, unsigned char *Data, unsigned char *Address, unsigned char *RetData);
extern__stdcall ISO7816_AUTH(int DeviceAddress, unsigned char Slot, unsigned char DataLen, unsigned char *Data, unsigned char *RetDataLen,unsigned char *RetData);
extern__stdcall ISO7816_AdminExec(int Deviceaddress, unsigned char Slot, unsigned char DataLen, unsigned char *Data, unsigned char *RetData);

#endif
