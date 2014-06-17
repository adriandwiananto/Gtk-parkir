#include "header.h"
#include <dirent.h>

#define COMMAND_LEN 20
#define DATA_SIZE 512

/*
Function for switching active window
*/
void WindowSwitcher(Bitwise WindowSwitcherFlag)
{
	if(config_checking() != 1)
	{
		gtk_main_quit();
	}
		
	/*password window switcher*/
	(f_password_window == TRUE)?gtk_widget_show(passwordwindow->window):gtk_widget_hide(passwordwindow->window);
	
	/*registration window switcher*/
	(f_registration_window == TRUE)?gtk_widget_show(registrationwindow->window):gtk_widget_hide(registrationwindow->window);
	
	/*registration window switcher*/
	if(f_in_ok_window == TRUE)
	{
		if(poll_pid != 0)
		{
			while(kill_nfc_poll_process() == FALSE){usleep(100000);};
		}
		
		gchar return_ndef[111];
		build_return_packet(return_ndef);
		gtk_widget_show(in_okwindow->window);
		return_nfc_poll_child_process(return_ndef);
	}
	else
	{
		gtk_widget_hide(in_okwindow->window);
	}

	/*main menu window switcher*/
	if(f_mainmenu_window == TRUE)
	{
		if(poll_pid != 0)
		{
			while(kill_nfc_poll_process() == FALSE){};
		}
		
		memset(&lastParkingData, 0, sizeof(lastParkingData));
		amount = 0;
		gtk_widget_show(mainmenuwindow->window);
		nfc_poll_child_process();
	}
	else
	{
		gtk_widget_hide(mainmenuwindow->window);
	}
	
	if(f_sending_window == TRUE)
	{
		gtk_widget_show(sendingWindow->window);
		if(f_sync_key)g_thread_new("send",build_and_send_keyRequest,NULL);
		else if(f_sync_in)g_thread_new("send",build_and_send_inData,NULL);
		else if(f_sync_out)g_thread_new("send",build_and_send_outData,NULL);
	}
	else
	{
		gtk_widget_hide(sendingWindow->window);
	}
}
