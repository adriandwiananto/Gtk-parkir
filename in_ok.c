#include "header.h"

/*
We call init_mainmenu_window() when our program is starting to load 
main menu window with references to Glade file. 
*/
gboolean init_in_ok_window()
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
	in_okwindow->window = GTK_WIDGET (gtk_builder_get_object (builder, "in_ok_window"));
	in_okwindow->label = GTK_WIDGET (gtk_builder_get_object (builder, "in_ok_label"));

	gtk_builder_connect_signals (builder, in_okwindow);
	g_object_unref(G_OBJECT(builder));
	
	return TRUE;
}

/* callback for Exit button in main menu window */
void on_in_ok_finish_button_clicked ()
{
	Bitwise WindowSwitcherFlag;
	f_status_window = FALSE;	//hide all window
	f_mainmenu_window = TRUE;		//show main window
	WindowSwitcher(WindowSwitcherFlag);
}

void build_return_packet(gchar* return_in_str)
{
	int i=0;
	unsigned char return_ndef_array[55];
	
	uintmax_t ACCN;
	gchar ACCNstr[32];
	ACCN = get_ACCN(ACCNstr);

	return_ndef_array[0] = 55; // length 55
	return_ndef_array[1] = 3; //offline
	return_ndef_array[2] = 1; //merchant
	memset(return_ndef_array+3,0,4);
	
	for(i=5; i>=0; i--)
	{
		if(i<5)ACCN >>= 8;
		return_ndef_array[7+i] = ACCN & 0xFF;
	}
	return_ndef_array[13] = strlen(lastParkingData.License);
	memcpy(return_ndef_array+14, lastParkingData.License, return_ndef_array[13]);
	if(return_ndef_array[13] < 9) memset(return_ndef_array+14+return_ndef_array[13], 0, 23-14-return_ndef_array[13]);
	memcpy(return_ndef_array+23, lastParkingData.park_key, 4);
	memset(return_ndef_array+27,12,12); //PADDING

	gchar* buf_ptr;

	unsigned char transKey[32];
	memset(transKey,0,32);
	
	unsigned char returnPayloadPlain[32];
	memcpy(returnPayloadPlain, return_ndef_array+7, 32);
	
	unsigned char returnPayloadEncrypted[32];
	memset(returnPayloadEncrypted,0,32);

	unsigned char aes_key[32];
	memset(aes_key,0,32);
	const gchar *passwordStr;
	passwordStr = gtk_entry_get_text(GTK_ENTRY(passwordwindow->text_entry));
	getTransKey(aes_key, passwordStr, ACCNstr, FALSE);
	
	unsigned char IV[16]; //, iv_dec[AES_BLOCK_SIZE];
	RAND_bytes(IV, 16);
	memcpy(return_ndef_array+39,IV,16);

	aes256cbc(returnPayloadEncrypted, returnPayloadPlain, aes_key, IV, "ENCRYPT");
	
	memcpy(return_ndef_array+7,returnPayloadEncrypted,32);

	buf_ptr = return_in_str;
	for (i = 0; i < 55; i++)
	{
		buf_ptr += sprintf((char*)buf_ptr, "%02X", return_ndef_array[i]);
	}
	*(buf_ptr + 1) = '\0';
	printf("receipt ndef in str: %s\n", return_in_str);
}

/* child process watch callback */
static void cb_child_watch( GPid pid, gint status, GString *data )
{
	data = g_string_new(NULL);
	
	//~ gtk_widget_hide(newtransNFCwindow->window);

	if (WIFEXITED(status))
	{
		switch(WEXITSTATUS(status))
		{
			case 0:
				break;
			case 1:
				error_message("Reader error! Reconnect reader!");
				break;
			case 2:
				break;
			case 3:
				error_message("Transaction failed! Retry tapping your phone again. (error:3)");
				break;
			case 4:
				error_message("Transaction failed! Retry tapping your phone again. (error:4)");
				break;
			case 5:
				error_message("Reader initialization FATAL error!");
				break;
			case 6:
				error_message("Wrong SESN input!");
				break;
			case 7:
				error_message("FATAL error!! Wrong transaction key!");
				break;
			default:
				error_message("Transaction failed! error:99");
				break;
		}
	}
	
	/* Close pid */
    g_spawn_close_pid( pid );
    
    g_string_free(data,TRUE);
}

/* io out watch callback */
static gboolean cb_out_watch( GIOChannel *channel, GIOCondition cond, GString *data )
{
	GIOStatus status;
	
	gchar detect_str[8];
	memset(detect_str,0,8);
	
	data = g_string_new(NULL);

    if( cond == G_IO_HUP )
    {
        g_io_channel_unref( channel );
        return( FALSE );
    }

    status = g_io_channel_read_line_string( channel, data, NULL, NULL );
 
    switch(status)
    {
		case G_IO_STATUS_EOF:
			printf("EOF\n");
			break;
			
		case G_IO_STATUS_NORMAL:
			memcpy(detect_str,data->str,5);
			if(!strcmp(detect_str,"DATA:"))
			{
				/*close receipt window and open main menu*/
				Bitwise WindowSwitcherFlag;
				f_status_window = FALSE;
				f_mainmenu_window = TRUE;
				WindowSwitcher(WindowSwitcherFlag);
			}
			
			break;
	
		case G_IO_STATUS_AGAIN: break;
		case G_IO_STATUS_ERROR:
		default:
			printf("Error stdout from child process\n");
			error_message("Error reading from child process");
			break;
	}
		
    g_string_free(data,TRUE);

    return( TRUE );
}

/* io err watch callback */
static gboolean cb_err_watch( GIOChannel *channel, GIOCondition cond, GString *data )
{
    gchar *string;
    gsize  size;
    
	data = g_string_new(NULL);

    if( cond == G_IO_HUP )
    {
        g_io_channel_unref( channel );
        return( FALSE );
    }

    g_io_channel_read_line( channel, &string, &size, NULL, NULL );
    fprintf(stderr,"%s",string);    
    g_free( string );
    g_string_free(data,TRUE);

    return( TRUE );
}

void return_nfc_poll_child_process(gchar* return_ndef)
{
	//~ const gchar *passwordStr;
	//~ passwordStr = gtk_entry_get_text(GTK_ENTRY(passwordwindow->text_entry));
	
    GPid        pid;
    gchar      *argv[] = { "./picc_emulation_read", return_ndef, NULL };
    gint        out,
                err;
    GIOChannel *out_ch,
               *err_ch;
    gboolean    ret;

	GString *data;
	data = g_string_new(NULL);
	//~ printf("SESN: %s\n",SESN);
    /* Spawn child process */
    ret = g_spawn_async_with_pipes( NULL, argv, NULL,
                                    G_SPAWN_DO_NOT_REAP_CHILD, NULL,
                                    data, &pid, NULL, &out, &err, NULL );
    if( ! ret )
    {
        g_error( "SPAWN FAILED" );
        return;
    }
    
	poll_pid = pid;
	
    /* Add watch function to catch termination of the process. This function
     * will clean any remnants of process. */
    g_child_watch_add( pid, (GChildWatchFunc)cb_child_watch, data );

    /* Create channels that will be used to read data from pipes. */
    out_ch = g_io_channel_unix_new( out );
    err_ch = g_io_channel_unix_new( err );

    /* Add watches to channels */
    g_io_add_watch( out_ch, G_IO_IN | G_IO_HUP, (GIOFunc)cb_out_watch, data );
    g_io_add_watch( err_ch, G_IO_IN | G_IO_HUP, (GIOFunc)cb_err_watch, data );
    
    g_string_free(data,TRUE);
}
