#include "header.h"
#include <libconfig.h>

static int cp(const char *to, const char *from);

int config_checking()
{
	config_t cfg;
	//~ config_setting_t *setting;
	//~ const char *str;

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if(! config_read_file(&cfg, "config.cfg"))
	{
		config_destroy(&cfg);
		return 2;
	}
	else if(! config_read_file(&cfg, "config1.cfg"))
	{
		config_destroy(&cfg);
		return -1;
	}
	else if(! config_read_file(&cfg, "config2.cfg"))
	{
		config_destroy(&cfg);
		return -1;
	}
	else
	{
		//config file for tamper checking goes here (compare hash value of redundant config files)
		char config_hash[65];
		char config1_hash[65];
		char config2_hash[65];
		if(calc_sha256_of_file("config.cfg", config_hash) != 0)
		{
			return -1;
		}
		if(calc_sha256_of_file("config1.cfg", config1_hash) != 0)
		{
			return -1;
		}
		if(calc_sha256_of_file("config2.cfg", config2_hash) != 0)
		{
			return -1;
		}
		
		if(strcmp(config_hash, config1_hash))
		{
			return -1;
		}
		if(strcmp(config_hash, config2_hash))
		{
			return -1;
		}
		if(strcmp(config1_hash, config2_hash))
		{
			return -1;
		}
		
		printf("config valid!\n");
		return 1;
	}
}	

gboolean create_new_config_file(uintmax_t ACCN, const char* password, char* HWID)
{
	config_t cfg;
	config_setting_t *root, *group, *setting;
	static const char *output_file = "config.cfg";
	
	/*libconfig init*/
	config_init(&cfg);
	root = config_root_setting(&cfg);
	
	/*create application group as root group*/
	group = config_setting_add(root, "application", CONFIG_TYPE_GROUP);
	
	/*create ACCN setting with INT64 type in application group*/
	setting = config_setting_add(group, "ACCN", CONFIG_TYPE_INT64);
	config_setting_set_int64(setting, ACCN);
	
	/*create Password setting with string type in application group*/
	setting = config_setting_add(group, "Pwd", CONFIG_TYPE_STRING);
	config_setting_set_string(setting, password);
	
	/*create HWID setting with string type in application group*/
	setting = config_setting_add(group, "HWID", CONFIG_TYPE_STRING);
	config_setting_set_string(setting, HWID);
	
	/*create LATS setting with INT64 type in application group*/
	setting = config_setting_add(group, "LATS", CONFIG_TYPE_INT64);
	config_setting_set_int64(setting, 0);
	
	/*create application group as root group*/
	group = config_setting_add(root, "security", CONFIG_TYPE_GROUP);
	
	/*create ACCN setting with INT64 type in application group*/
	setting = config_setting_add(group, "transaction", CONFIG_TYPE_STRING);
	config_setting_set_string(setting, "EMPTY");
	
	/* Write out the new configuration. */
	if(! config_write_file(&cfg, output_file))
	{
		fprintf(stderr, "Error while writing file.\n");
		config_destroy(&cfg);
		return FALSE;
	}

	fprintf(stdout, "New configuration successfully written to: %s\n", output_file);

	config_destroy(&cfg);
	
	if(cp("config1.cfg","config.cfg") == 0)
	{
		if(cp("config2.cfg","config.cfg") == 0)
			return TRUE;
	}
	
	return FALSE;
}

gboolean get_INT64_from_config(uintmax_t *value, const char *path)
{
	config_t cfg;

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if(! config_read_file(&cfg, "config.cfg"))
	{
		config_destroy(&cfg);
		return FALSE;	//return error
	}

	/* Get ACCN. */
	if(config_lookup_int64(&cfg, path, (long long int *)value))
	{
		config_destroy(&cfg);
		return TRUE;
	}
	else
	{
		fprintf(stderr, "No mentioned setting in configuration file.\n");
		config_destroy(&cfg);
		return FALSE;
	}
}

gboolean get_string_from_config(char *value, const char *path)
{
	const char *str_in_config;
	config_t cfg;

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if(! config_read_file(&cfg, "config.cfg"))
	{
		config_destroy(&cfg);
		return FALSE;	//return error
	}

	/* Get pwd. */
	if(config_lookup_string(&cfg, path, &str_in_config))
	{
		memcpy(value, str_in_config, strlen(str_in_config));
		config_destroy(&cfg);
		return TRUE;
	}
	else
	{
		fprintf(stderr, "No mentioned setting in configuration file.\n");
		config_destroy(&cfg);
		return FALSE;
	}
}

gboolean write_string_to_config(char *value, const char *path)
{
	static const char *output_file = "config.cfg";
	config_t cfg;
	config_setting_t *setting;
	
	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if(! config_read_file(&cfg, "config.cfg"))
	{
		config_destroy(&cfg);
		return FALSE;	//return error
	}

	setting = config_lookup(&cfg, path);
	
	/* write string */
	if(config_setting_set_string(setting, value))
	{
		/* Write out the new configuration. */
		if(! config_write_file(&cfg, output_file))
		{
			fprintf(stderr, "Error while writing file.\n");
			config_destroy(&cfg);
			return FALSE;
		}

		fprintf(stdout, "New configuration successfully written to: %s\n", output_file);
		config_destroy(&cfg);
	}
	else
	{
		fprintf(stderr, "No mentioned setting in configuration file.\n");
		config_destroy(&cfg);
		return FALSE;
	}
	
	if(cp("config1.cfg","config.cfg") == 0)
	{
		if(cp("config2.cfg","config.cfg") == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

gboolean write_int64_to_config(uintmax_t value, const char *path)
{
	static const char *output_file = "config.cfg";
	config_t cfg;
	config_setting_t *setting;
	
	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if(! config_read_file(&cfg, "config.cfg"))
	{
		config_destroy(&cfg);
		return FALSE;	//return error
	}

	setting = config_lookup(&cfg, path);
	
	/* write string */
	if(config_setting_set_int64(setting, value))
	{
		/* Write out the new configuration. */
		if(! config_write_file(&cfg, output_file))
		{
			fprintf(stderr, "Error while writing file.\n");
			config_destroy(&cfg);
			return FALSE;
		}

		fprintf(stdout, "New configuration successfully written to: %s\n", output_file);
		config_destroy(&cfg);
	}
	else
	{
		fprintf(stderr, "No mentioned setting in configuration file.\n");
		config_destroy(&cfg);
		return FALSE;
	}
	
	if(cp("config1.cfg","config.cfg") == 0)
	{
		if(cp("config2.cfg","config.cfg") == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

static int cp(const char *to, const char *from)
{
    int fd_to, fd_from;
    char buf[4096];
    ssize_t nread;
    int saved_errno;

    fd_from = open(from, O_RDONLY);
    if (fd_from < 0)
        return -1;

	fd_to = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		
    if (fd_to < 0)
        goto out_error;

    while (nread = read(fd_from, buf, sizeof buf), nread > 0)
    {
        char *out_ptr = buf;
        ssize_t nwritten;

        do {
            nwritten = write(fd_to, out_ptr, nread);

            if (nwritten >= 0)
            {
                nread -= nwritten;
                out_ptr += nwritten;
            }
            else if (errno != EINTR)
            {
                goto out_error;
            }
        } while (nread > 0);
    }

    if (nread == 0)
    {
        if (close(fd_to) < 0)
        {
            fd_to = -1;
            goto out_error;
        }
        close(fd_from);

        /* Success! */
        return 0;
    }

  out_error:
    saved_errno = errno;

    close(fd_from);
    if (fd_to >= 0)
        close(fd_to);

    errno = saved_errno;
    return -1;
}

/*function for getting ACCN value from config file*/
/*ACCN_inString size must be 32*/
uintmax_t get_ACCN(gchar* ACCN_inString)
{
	uintmax_t ACCN = 0;
	memset(ACCN_inString, 0, 32);
	
	if(get_INT64_from_config(&ACCN, "application.ACCN") == TRUE)
	{
		sprintf(ACCN_inString, "%ju", ACCN);
#ifdef DEBUG_MODE
		printf("ACCN get_ACCN: %ju\n",ACCN);
		printf("ACCNstr get_ACCN: %s\n",ACCN_inString);
#endif
	}
	else
	{
		strcpy(ACCN_inString,"error!");
	}
	
	return ACCN;
}
