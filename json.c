#include "header.h"

const char* get_key_inString_from_json_response(json_object* jobj)
{
	json_object* jobj_parse;
	
	jobj_parse = json_object_object_get(jobj, "key");
	
	return json_object_get_string(jobj_parse);
}

json_object* create_registration_json(uintmax_t ACCN, int HWID)
{
	gchar ACCNstr[32];
	memset(ACCNstr, 0, 32);
	sprintf(ACCNstr,"%ju",ACCN);
	
	/*Creating a json object*/
	json_object * jobj = json_object_new_object();

	/*Creating a json string*/
	//~ json_object *jint64_ACCN = json_object_new_int64(ACCN);
	json_object *jint64_ACCN = json_object_new_string(ACCNstr);

	/*Creating a json string*/
	json_object *jint_HWID = json_object_new_int(HWID);

	/*Form the json object*/
	/*Each of these is like a key value pair*/
	json_object_object_add(jobj,"ACCN", jint64_ACCN);
	json_object_object_add(jobj,"HWID", jint_HWID);
	
	return jobj;
}

//~ json_object* create_log_as_json_object()
//~ {
	//~ json_object * jobj_root = json_object_new_object();
	//~ json_object * jobj_header = json_object_new_object();
	//~ json_object * jobj_logs = json_object_new_array();
	//~ 
	//~ int numOfLog = logNum();
	//~ int i = 0;
	//~ 
	//~ unsigned char LogKey[32];
	//~ memset(LogKey,0,32);
	//~ 
	//~ if(getLogKey(LogKey)==TRUE)
	//~ {
		//~ for(i=1;i<=numOfLog;i++)
		//~ {
			//~ json_object * jobj_log_object = json_object_new_object();
			//~ 
			//~ unsigned char fromDB[96];
			//~ memset(fromDB,0,96);
			//~ int logLen = read_log_blob(fromDB, i);
			//~ if(logLen == 96)
			//~ {
				//~ unsigned char fromDBbyte[48];
				//~ memset(fromDBbyte,0,48);
				//~ hexstrToBinArr(fromDBbyte,(gchar*)fromDB,48);
				//~ 
				//~ unsigned char IV[16];
				//~ memset(IV,0,16);
				//~ memcpy(IV,fromDBbyte+32,16);
				//~ 
				//~ unsigned char logDecrypted[32];
				//~ memset(logDecrypted,0,32);
				//~ 
				//~ aes256cbc(logDecrypted, fromDBbyte, LogKey, IV, "DECRYPT");
				//~ 
				//~ unsigned int NUM = logDecrypted[0]<<16 |  logDecrypted[1]<<8 | logDecrypted[2];
				//~ int PT = logDecrypted[3];
				//~ unsigned int BinID = logDecrypted[4]<<24 | logDecrypted[5]<<16 |  logDecrypted[6]<<8 | logDecrypted[7];
				//~ 
				//~ uintmax_t ACCN_M, ACCN_P;
				//~ ACCN_M=0;
				//~ ACCN_P=0;
				//~ 
				//~ int z=0;
				//~ for(z=0; z<6; z++)
				//~ {
					//~ if(z)
					//~ {
						//~ ACCN_M <<= 8;
						//~ ACCN_P <<= 8;
					//~ }
					//~ ACCN_M |= logDecrypted[8+z];
					//~ ACCN_P |= logDecrypted[14+z];
				//~ }
				//~ 
				//~ ACCN_M &= 0xFFFFFFFFFFFF;
				//~ ACCN_P &= 0xFFFFFFFFFFFF;
				//~ 
				//~ unsigned int AMNT = logDecrypted[20]<<24 | logDecrypted[21]<<16 |  logDecrypted[22]<<8 | logDecrypted[23];
				//~ unsigned int TS = logDecrypted[24]<<24 | logDecrypted[25]<<16 |  logDecrypted[26]<<8 | logDecrypted[27];
				//~ int STAT = logDecrypted[28];
				//~ int CNL = logDecrypted[29];
				//~ 
				//~ json_object * jint_NUM = json_object_new_int(NUM);
				//~ json_object * jint_PT = json_object_new_int(PT);
				//~ json_object * jint_BinaryID = json_object_new_int(BinID);
				//~ json_object * jint64_ACCN_M = json_object_new_int64(ACCN_M);
				//~ json_object * jint64_ACCN_P = json_object_new_int64(ACCN_P);
				//~ json_object * jint_AMNT = json_object_new_int(AMNT);
				//~ json_object * jint_TS = json_object_new_int(TS);
				//~ json_object * jint_STAT = json_object_new_int(STAT);
				//~ json_object * jint_CNL = json_object_new_int(CNL);
				//~ 
				//~ json_object_object_add(jobj_log_object,"NUM", jint_NUM);
				//~ json_object_object_add(jobj_log_object,"PT", jint_PT);
				//~ json_object_object_add(jobj_log_object,"BinaryID", jint_BinaryID);
				//~ json_object_object_add(jobj_log_object,"ACCN-M", jint64_ACCN_M);
				//~ json_object_object_add(jobj_log_object,"ACCN-P", jint64_ACCN_P);
				//~ json_object_object_add(jobj_log_object,"AMNT", jint_AMNT);
				//~ json_object_object_add(jobj_log_object,"TS", jint_TS);
				//~ json_object_object_add(jobj_log_object,"STAT", jint_STAT);
				//~ json_object_object_add(jobj_log_object,"CNL", jint_CNL);
			//~ }
			//~ json_object_array_add(jobj_logs, jobj_log_object);
		//~ }
	//~ }
	//~ 
//~ #ifdef DEBUG_MODE
	//~ printf("json logs: %s\n", json_object_to_json_string(jobj_logs));
//~ #endif
	//~ 
	//~ uintmax_t ACCN;
	//~ json_object * jint_ACCN;
	//~ if(get_INT64_from_config(&ACCN, "application.ACCN") == TRUE)
		//~ jint_ACCN = json_object_new_int64(ACCN);
	//~ 
	//~ char HWID[16];
	//~ memset(HWID,0,16);
	//~ json_object * jint_HWID;
	//~ if(get_USB_reader_HWID(HWID) == TRUE)
	//~ {
		//~ int HWIDint = strtoimax(HWID,NULL,10);
		//~ jint_HWID = json_object_new_int(HWIDint);
	//~ }
	//~ else
	//~ {
		//~ return json_object_new_object();
	//~ }
	//~ 
	//~ json_object *jint_numOfLog = json_object_new_int(numOfLog);
	//~ 
	//~ uintmax_t LATS;
	//~ json_object * jint_last_sync_at;
	//~ if(get_INT64_from_config(&LATS, "application.LATS") == TRUE)
		//~ jint_last_sync_at = json_object_new_int((int)LATS);
	//~ 
	//~ char signature[(2*SHA256_DIGEST_LENGTH)+1];
	//~ memset(signature, 0, (2*SHA256_DIGEST_LENGTH)+1);
//~ 
	//~ json_log_array_hashing(signature, json_object_to_json_string(jobj_logs));
	//~ printf("signature:%s\n",signature);
//~ 
	//~ json_object * jstr_signature = json_object_new_string(signature);
	//~ printf("signature:%s\n",json_object_to_json_string(jstr_signature));
//~ 
	//~ json_object * jint_balance;
	//~ jint_balance = json_object_new_int(settlementwindow->settlement_balance);
	//~ printf("balance:%s\n",json_object_to_json_string(jint_balance));
	//~ 
	//~ json_object_object_add(jobj_header,"ACCN",jint_ACCN);
	//~ printf("json object header:%s\n",json_object_to_json_string(jobj_header));
//~ 
	//~ json_object_object_add(jobj_header,"HWID",jint_HWID);
	//~ printf("json object header:%s\n",json_object_to_json_string(jobj_header));
//~ 
	//~ json_object_object_add(jobj_header,"numOfLog",jint_numOfLog);
	//~ printf("json object header:%s\n",json_object_to_json_string(jobj_header));
//~ 
	//~ json_object_object_add(jobj_header,"signature",jstr_signature);
	//~ printf("json object header:%s\n",json_object_to_json_string(jobj_header));
//~ 
	//~ json_object_object_add(jobj_header,"last_sync_at",jint_last_sync_at);
	//~ printf("json object header:%s\n",json_object_to_json_string(jobj_header));
//~ 
	//~ json_object_object_add(jobj_header,"balance",jint_balance);
	//~ printf("json object header:%s\n",json_object_to_json_string(jobj_header));
//~ 
//~ #ifdef DEBUG_MODE
	//~ printf("json header: %s\n", json_object_to_json_string(jobj_header));
//~ #endif
//~ 
	//~ json_object_object_add(jobj_root,"header",jobj_header);
	//~ json_object_object_add(jobj_root,"logs",jobj_logs);
	//~ 
//~ #ifdef DEBUG_MODE
	//~ printf("json root: %s\n", json_object_to_json_string(jobj_root));
//~ #endif
//~ 
	//~ return jobj_root;
//~ }
