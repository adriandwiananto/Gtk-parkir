/* credits for init_string and callback function to: 
 * http://stackoverflow.com/a/2329792/3095632
 */

#include "header.h"

static void init_string(ResponseString *s) 
{
	s->len = 0;
	s->ptr = malloc(s->len+1);
	if (s->ptr == NULL) 
	{
		fprintf(stderr, "malloc() failed\n");
		exit(EXIT_FAILURE);
	}
	s->ptr[0] = '\0';
}

static size_t curl_response_to_string(void *ptr, size_t size, size_t nmemb, ResponseString *s)
{
	size_t new_len = s->len + size*nmemb;
	s->ptr = realloc(s->ptr, new_len+1);
	if (s->ptr == NULL) 
	{
		fprintf(stderr, "realloc() failed\n");
		exit(EXIT_FAILURE);
	}
	memcpy(s->ptr+s->len, ptr, size*nmemb);
	s->ptr[new_len] = '\0';
	s->len = new_len;

	return size*nmemb;
}

gboolean send_reg_jsonstring_to_server(gchar* aesKeyString, unsigned int* retTS, const char* jsonString, const char* serverName)
{
	CURL *curl;
	CURLcode res;

	char *dataBuffer;
	dataBuffer = (char *) malloc ((strlen(jsonString)+5)*sizeof(char));
	if(dataBuffer == NULL) 
		return FALSE;
	
	memset(dataBuffer,0,sizeof(dataBuffer));
	strcpy(dataBuffer,"data=");
	memcpy(dataBuffer+5,jsonString, strlen(jsonString));

#ifdef DEBUG_MODE	
	printf("dataBuffer = %s\n",dataBuffer);
#endif

	/* get a curl handle */ 
	curl = curl_easy_init();
	if(curl) 
	{
		ResponseString response;
		init_string(&response);
		
		/* First set the URL that is about to receive our POST. This URL can
		just as well be a https:// URL if that is what should receive the
		data. */ 
		curl_easy_setopt(curl, CURLOPT_URL, serverName);
		
		/* Now specify the POST data */ 
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, dataBuffer);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_response_to_string);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		
		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		
		/* Check for errors */ 
		if(res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			free(response.ptr);
			curl_easy_cleanup(curl);
			return FALSE;
		}
		
#ifdef DEBUG_MODE		
		printf("response in string:%s\n", response.ptr);
		printf("length:%d\n", response.len);
#endif
		
		//~ memcpy(serverResponse, response.ptr, response.len);
		json_object * jobj_response = json_tokener_parse(response.ptr);
		
		//if error == null (no json object error), continue
		//otherwise internal server error
		json_object * error_object = json_object_object_get(jobj_response, "error");
		if(strcmp(json_object_to_json_string(error_object),"null"))
			return FALSE;
			
		json_object * response_status = json_object_object_get(jobj_response,"result");
		if(!strcmp(json_object_get_string(response_status),"Error"))
			return FALSE;
		if(!strcmp(json_object_get_string(response_status),"error"))
			return FALSE;
			
		json_object* json_key = json_object_object_get(jobj_response, "key");
		memcpy(aesKeyString, json_object_get_string(json_key), strlen(json_object_get_string(json_key)));

		json_object* json_TS = json_object_object_get(jobj_response, "last_sync_at");
		*retTS = json_object_get_int(json_TS);

		free(response.ptr);
		
		/* always cleanup */ 
		curl_easy_cleanup(curl);
	}

	return TRUE;
}

gboolean send_key_request_to_server(gchar* ACCNM, gchar* timestamp, gchar* aesKeyString, const char* serverName)
{
	const char *accnmPost = "ACCN=";
	const char *timestampPost = "&last_sync_at=";
	CURL *curl;
	CURLcode res;

	char *dataBuffer;
	int total_len = strlen(accnmPost)+strlen(ACCNM)+strlen(timestampPost)+strlen(timestamp);
	
	dataBuffer = (char *) malloc (total_len+1);
	if(dataBuffer == NULL) 
		return FALSE;
	
	int index = 0;
	
	memset(dataBuffer,0,total_len+1);

	//ACCN-M
	memcpy(dataBuffer,accnmPost,strlen(accnmPost));
	index += strlen(accnmPost);
	
	memcpy(dataBuffer+index,ACCNM, strlen(ACCNM));
	index += strlen(ACCNM);
	
	//timestamp
	memcpy(dataBuffer+index,timestampPost,strlen(timestampPost));
	index += strlen(timestampPost);
	
	memcpy(dataBuffer+index,timestamp, strlen(timestamp));
	index += strlen(timestamp);
	
	dataBuffer[index] = '\0';

#ifdef DEBUG_MODE	
	printf("dataBuffer:%s\n",dataBuffer);
#endif

	/* get a curl handle */ 
	curl = curl_easy_init();
	if(curl) 
	{
		ResponseString response;
		init_string(&response);
		
		/* First set the URL that is about to receive our POST. This URL can
		just as well be a https:// URL if that is what should receive the
		data. */ 
		curl_easy_setopt(curl, CURLOPT_URL, serverName);
		
		/* Now specify the POST data */ 
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, dataBuffer);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_response_to_string);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		
		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		
		/* Check for errors */ 
		if(res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			return FALSE;
		}
		
#ifdef DEBUG_MODE		
		printf("response in string:%s\n", response.ptr);
		printf("response length:%d\n", response.len);
#endif
		
		//memcpy(serverResponse, response.ptr, response.len);
		json_object * jobj_response_root = json_tokener_parse(response.ptr);
		
		json_object * error_object = json_object_object_get(jobj_response_root, "error");
		if(strcmp(json_object_to_json_string(error_object),"null"))
			return FALSE;

		json_object * jobj_response_result = json_object_object_get(jobj_response_root, "result");
		if(!strcmp(json_object_get_string(jobj_response_result),"Error"))
			return FALSE;
		if(!strcmp(json_object_get_string(jobj_response_result),"error"))
			return FALSE;
		
		json_object * jobj_response_key = json_object_object_get(jobj_response_root, "key");
		json_object * jobj_response_key_renew = json_object_object_get(jobj_response_key, "renew");
		if(json_object_get_boolean(jobj_response_key_renew) == TRUE){
			printf("renew!\n");
			json_object * jobj_response_key_new_key = json_object_object_get(jobj_response_key, "new_key");
			memcpy(aesKeyString, json_object_get_string(jobj_response_key_new_key), strlen(json_object_get_string(jobj_response_key_new_key)));
		}

		write_int64_to_config((uintmax_t)time(NULL), "application.LATS");
		free(response.ptr);
		
		/* always cleanup */ 
		curl_easy_cleanup(curl);
	}
	
	return TRUE;
}

gboolean send_in_data_to_server(gchar* ACCNM, const char* serverName)
{
	const char *accnmPost = "ACCN=";
	const char *licensePost = "&licence=";
	CURL *curl;
	CURLcode res;

	char *dataBuffer;
	int total_len = strlen(accnmPost)+
	strlen(ACCNM)+
	strlen(licensePost)+
	strlen(lastParkingData.License);
	
	dataBuffer = (char *) malloc (total_len+1);
	if(dataBuffer == NULL) 
		return FALSE;
	
	int index = 0;
	
	memset(dataBuffer,0,total_len+1);

	//ACCN-M
	memcpy(dataBuffer,accnmPost,strlen(accnmPost));
	index += strlen(accnmPost);
	
	memcpy(dataBuffer+index,ACCNM, strlen(ACCNM));
	index += strlen(ACCNM);
	
	//license
	memcpy(dataBuffer+index,licensePost,strlen(licensePost));
	index += strlen(licensePost);
	
	memcpy(dataBuffer+index,lastParkingData.License, strlen(lastParkingData.License));
	index += strlen(lastParkingData.License);
	
	dataBuffer[index] = '\0';

#ifdef DEBUG_MODE	
	printf("dataBuffer:%s\n",dataBuffer);
#endif

	/* get a curl handle */ 
	curl = curl_easy_init();
	if(curl) 
	{
		ResponseString response;
		init_string(&response);
		
		/* First set the URL that is about to receive our POST. This URL can
		just as well be a https:// URL if that is what should receive the
		data. */ 
		curl_easy_setopt(curl, CURLOPT_URL, serverName);
		
		/* Now specify the POST data */ 
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, dataBuffer);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_response_to_string);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		
		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		
		/* Check for errors */ 
		if(res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			return FALSE;
		}
		
#ifdef DEBUG_MODE		
		printf("response in string:%s\n", response.ptr);
		printf("response length:%d\n", response.len);
#endif
		
		//memcpy(serverResponse, response.ptr, response.len);
		json_object * jobj_response_root = json_tokener_parse(response.ptr);
		
		json_object * error_object = json_object_object_get(jobj_response_root, "error");
		if(strcmp(json_object_to_json_string(error_object),"null"))
			return FALSE;

		json_object * jobj_response_result = json_object_object_get(jobj_response_root, "result");
		if(!strcmp(json_object_get_string(jobj_response_result),"Error"))
			return FALSE;
		if(!strcmp(json_object_get_string(jobj_response_result),"error"))
			return FALSE;
		
		json_object * jobj_response_status = json_object_object_get(jobj_response_root, "status");
		if(strcmp(json_object_get_string(jobj_response_status),"in"))
			return FALSE;
			
		json_object * jobj_response_park_key = json_object_object_get(jobj_response_root, "park_key");
		lastParkingData.park_key_long = strtoumax(json_object_get_string(jobj_response_park_key), NULL, 10);
		lastParkingData.park_key[0] = (int)((lastParkingData.park_key_long >> 24) & 0xFF) ;
		lastParkingData.park_key[1] = (int)((lastParkingData.park_key_long >> 16) & 0xFF) ;
		lastParkingData.park_key[2] = (int)((lastParkingData.park_key_long >> 8) & 0XFF);
		lastParkingData.park_key[3] = (int)((lastParkingData.park_key_long & 0XFF));

		free(response.ptr);
		
		/* always cleanup */ 
		curl_easy_cleanup(curl);
	}
	
	return TRUE;
}

gboolean send_out_data_to_server(gchar* ACCNM, const char* serverName)
{
	const char *accnmPost = "ACCN=";
	const char *licensePost = "&licence=";
	const char *parkkeyPost = "&park_key=";
	CURL *curl;
	CURLcode res;

	gchar park_key_str[32];
	sprintf(park_key_str, "%lu", lastParkingData.park_key_long);
	
	char *dataBuffer;
	int total_len = strlen(accnmPost)+strlen(ACCNM)+strlen(licensePost)+strlen(lastParkingData.License)+strlen(parkkeyPost)+strlen(park_key_str);
	
	dataBuffer = (char *) malloc (total_len+1);
	if(dataBuffer == NULL) 
		return FALSE;
	
	int index = 0;
	
	memset(dataBuffer,0,total_len+1);

	//ACCN-M
	memcpy(dataBuffer,accnmPost,strlen(accnmPost));
	index += strlen(accnmPost);
	
	memcpy(dataBuffer+index,ACCNM, strlen(ACCNM));
	index += strlen(ACCNM);
	
	//license
	memcpy(dataBuffer+index,licensePost,strlen(licensePost));
	index += strlen(licensePost);
	
	memcpy(dataBuffer+index,lastParkingData.License, strlen(lastParkingData.License));
	index += strlen(lastParkingData.License);
	
	//park key
	memcpy(dataBuffer+index,parkkeyPost,strlen(parkkeyPost));
	index += strlen(parkkeyPost);
	
	memcpy(dataBuffer+index,park_key_str, strlen(park_key_str));
	index += strlen(park_key_str);
	
	dataBuffer[index] = '\0';

#ifdef DEBUG_MODE	
	printf("dataBuffer:%s\n",dataBuffer);
#endif

	/* get a curl handle */ 
	curl = curl_easy_init();
	if(curl) 
	{
		ResponseString response;
		init_string(&response);
		
		/* First set the URL that is about to receive our POST. This URL can
		just as well be a https:// URL if that is what should receive the
		data. */ 
		curl_easy_setopt(curl, CURLOPT_URL, serverName);
		
		/* Now specify the POST data */ 
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, dataBuffer);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_response_to_string);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		
		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		
		/* Check for errors */ 
		if(res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			return FALSE;
		}
		
#ifdef DEBUG_MODE		
		printf("response in string:%s\n", response.ptr);
		printf("response length:%d\n", response.len);
#endif
		
		//memcpy(serverResponse, response.ptr, response.len);
		json_object * jobj_response_root = json_tokener_parse(response.ptr);
		
		json_object * error_object = json_object_object_get(jobj_response_root, "error");
		if(strcmp(json_object_to_json_string(error_object),"null"))
			return FALSE;

		json_object * jobj_response_result = json_object_object_get(jobj_response_root, "result");
		if(!strcmp(json_object_get_string(jobj_response_result),"Error"))
			return FALSE;
		if(!strcmp(json_object_get_string(jobj_response_result),"error"))
			return FALSE;
		
		json_object * jobj_response_status = json_object_object_get(jobj_response_root, "status");
		if(strcmp(json_object_get_string(jobj_response_status),"out"))
			return FALSE;
			
		json_object * jobj_response_amount = json_object_object_get(jobj_response_root, "amount");
		amount = json_object_get_int(jobj_response_amount);
		
		free(response.ptr);
		
		/* always cleanup */ 
		curl_easy_cleanup(curl);
	}
	
	return TRUE;
}
