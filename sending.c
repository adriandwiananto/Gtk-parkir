#include "header.h"

/*
We call init_mainmenu_window() when our program is starting to load 
main menu window with references to Glade file. 
*/
gboolean init_sending_window()
{
	GtkBuilder              *builder;
	GError                  *err=NULL;

	/* use GtkBuilder to build our interface from the XML file */
	builder = gtk_builder_new ();
	if (gtk_builder_add_from_file (builder, UI_GLADE_FILE, &err) == 0)
	{
		error_message (err->message);
		g_error_free (err);
		return FALSE;
	}

	/* get the widgets which will be referenced in callbacks */
	sendingWindow->window = GTK_WIDGET (gtk_builder_get_object (builder, "sending_window"));
	sendingWindow->label = GTK_WIDGET (gtk_builder_get_object (builder, "sending_label"));

	gtk_builder_connect_signals (builder, sendingWindow);
	g_object_unref(G_OBJECT(builder));
	
	return TRUE;
}

gpointer build_and_send_keyRequest(gpointer nothing)
{
	gchar ACCNstr[32];
	get_ACCN(ACCNstr);
	
	uintmax_t LATS;
	get_INT64_from_config(&LATS, "application.LATS");
	gchar LATSstr[32];
	sprintf(LATSstr, "%ju", LATS);

	gchar aesKeyString[65];
	memset(aesKeyString,0,65);
	
	if(send_key_request_to_server(ACCNstr, LATSstr, aesKeyString, "https://emoney-server.herokuapp.com/get_key.json") == FALSE)
	{
		g_idle_add(sending_finish, "Error sync key!");
		return NULL;
	}
	
	if(strlen(aesKeyString) > 1)
	{
		printf("renew to: %s\n", aesKeyString);
		
		unsigned char aes_key[KEY_LEN_BYTE];
		memset(aes_key,0,KEY_LEN_BYTE);
		hexstrToBinArr(aes_key, aesKeyString, 32);
		
		const gchar * pwd = gtk_entry_get_text(GTK_ENTRY(passwordwindow->text_entry));
		printf("pwd: %s\n",pwd);
		
		if(set_new_key(aes_key, pwd, ACCNstr) == FALSE)
			g_idle_add(sending_finish, "Error writing key!");
			return NULL;
	}
	g_idle_add(sending_finish, "Success sync key!");
	return NULL;
}

gpointer build_and_send_inData(gpointer nothing)
{
	gchar ACCNstr[32];
	get_ACCN(ACCNstr);

	if(send_in_data_to_server(ACCNstr, "https://emoney-server.herokuapp.com/park.json") == FALSE)
	{
		g_idle_add(sending_finish, "Error in data!");
		return NULL;
	}
	
	g_idle_add(sending_finish, "Success in data!");
	return NULL;
}

gpointer build_and_send_outData(gpointer nothing)
{
	gchar ACCNstr[32];
	get_ACCN(ACCNstr);
	
	if(send_out_data_to_server(ACCNstr, "https://emoney-server.herokuapp.com/park.json") == FALSE)
	{
		g_idle_add(sending_finish, "Error out data!");
		return NULL;
	}
	
	g_idle_add(sending_finish, "Success out data!");
	return NULL;
}

gboolean sending_finish(gpointer message)
{
	if(!strcmp((const char*)message, "Success sync key!"))
	{
		Bitwise WindowSwitcherFlag;
		f_status_window = FALSE;	//hide all window
		f_mainmenu_window = TRUE;		//show main window
		WindowSwitcher(WindowSwitcherFlag);
	}
	else if(!strcmp((const char*)message, "Error sync key!") || !strcmp((const char*)message, "Error writing key!"))
	{
		Bitwise WindowSwitcherFlag;
		f_status_window = FALSE;	//hide all window
		f_password_window = TRUE;		//show main window
		WindowSwitcher(WindowSwitcherFlag);
		error_message((const gchar*) message);
	}
	else if(!strcmp((const char*)message, "Success in data!"))
	{
		Bitwise WindowSwitcherFlag;
		f_status_window = FALSE;	//hide all window
		f_in_ok_window = TRUE;		//show main window
		WindowSwitcher(WindowSwitcherFlag);
	}
	else if(!strcmp((const char*)message, "Error in data!"))
	{
		Bitwise WindowSwitcherFlag;
		f_status_window = FALSE;	//hide all window
		f_mainmenu_window = TRUE;		//show main window
		WindowSwitcher(WindowSwitcherFlag);
		error_message((const gchar*) message);
	}		
	else if(!strcmp((const char*)message, "Success out data!"))
	{
		Bitwise WindowSwitcherFlag;
		f_status_window = FALSE;	//hide all window
		//~ f_mainmenu_window = TRUE;		//show main window
		WindowSwitcher(WindowSwitcherFlag);
		
		char notif_msg[256];
		snprintf(notif_msg, 256, "License: %s\nAmount: Rp %'d", lastParkingData.License, amount);
		notification_message(notif_msg);
		
		f_status_window = FALSE;	//hide all window
		f_mainmenu_window = TRUE;		//show main window
		WindowSwitcher(WindowSwitcherFlag);
	}
	else if(!strcmp((const char*)message, "Error out data!"))
	{
		Bitwise WindowSwitcherFlag;
		f_status_window = FALSE;	//hide all window
		f_mainmenu_window = TRUE;		//show main window
		WindowSwitcher(WindowSwitcherFlag);
		error_message((const gchar*) message);
	}		
	return FALSE;
}
