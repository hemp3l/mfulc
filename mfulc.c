/*
 * Copyright (c) 2023, Nico Leidecker
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the organization nor the names of its contributors 
 *       may be used to endorse or promote products derived from this software 
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <nfc/nfc.h>
#include <freefare.h>

#define ACTION_NONE 0
#define ACTION_READ	1
#define ACTION_WRITE 2
#define ACTION_INFO 3

#define POLL_NUM	0xff	// 0xff = endless polling
#define POLL_PERIOD 0x0f		// 0xf= 2.25s

#define MAX_DEVICES 4
#define LAST_PAGE 43 	// for UL/C = 43 | EV1 = 

#define ULC_DEFAULT_KEY { 0x49, 0x45, 0x4D, 0x4B, 0x41, 0x45, 0x52, 0x42, 0x21, 0x4E, 0x41, 0x43, 0x55, 0x4F, 0x59, 0x46 }

#define BANNER "mfulc - MiFare Ultralight/C Tool\n"

bool quiet = false;

#define verb_print(args...) 	if (!quiet) { \
									printf(args); \
									fflush(stdout); \
								}


/*
	TODO: 
		test if auth is required for ul/c
		test if auth0/auth1 can be written
*/



uint8_t *get_version(nfc_device *device) 
{

	uint8_t resp[264];

printf("getting version\n");
// Configure the CRC
  if (nfc_device_set_property_bool(device, NP_HANDLE_CRC, false) < 0) {
    nfc_perror(device, "nfc_configure");
    return NULL;
  }
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(device, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(device, "nfc_configure");
    return NULL;
  }


	uint8_t  get_version_cmd[3] = { 0x60, 0x00, 0x00 };
	iso14443a_crc_append(get_version_cmd, 1);

	// transmit

	printf("going to transceive\n");
	int size_resp = nfc_initiator_transceive_bytes(device, get_version_cmd, 3, resp, sizeof(resp), 0);
	if (size_resp < 0) {
		return NULL;
	}
	printf("done: %i\n", size_resp);
	for (int i = 0; i < size_resp; i++) {
		printf("%.2X", resp[i]);
	}
	printf("\n");

	
  // reset reader
  // Configure the CRC
  if (nfc_device_set_property_bool(device, NP_HANDLE_CRC, true) < 0) {
    nfc_perror(device, "nfc_device_set_property_bool");
    return NULL;
  }
  // Switch off raw send/receive methods
  if (nfc_device_set_property_bool(device, NP_EASY_FRAMING, true) < 0) {
    nfc_perror(device, "nfc_device_set_property_bool");
    return NULL;
  }

  printf("completed\n");
  sleep(1);
  return NULL;
}

// initialise libnfc, list devices and connect to chosen device
nfc_device *connect_device(unsigned short device_id)
{
	nfc_context *context;
	nfc_connstring devices[MAX_DEVICES];
	int dev_idx;
	int dev_num;
	const char *libnfc_version;
	nfc_device *device;

	// initialize libnfc
	nfc_init(&context);
	if (!context) {
    	fprintf(stderr, "Unable to initialize libnfc\n");
	    exit(EXIT_FAILURE);
   	}

   	// show libnfc version
   	libnfc_version = nfc_version();
   	verb_print("libnfc version: %s\n", libnfc_version);


	// list all attached devices
	dev_num = nfc_list_devices(context, devices, MAX_DEVICES);
	if (dev_num == 0) {
		fprintf(stderr, "no nfc device attached\n");
	    exit(EXIT_FAILURE);
	}

	verb_print("--------------------------\n");
	verb_print("List of devices:\n");

	for (dev_idx = 0; dev_idx < dev_num; dev_idx++) {
		verb_print("(%i) %s\n", dev_idx, devices[dev_idx]);
	}
	verb_print("--------------------------\n");

	if (device_id >= dev_num) {
		fprintf(stderr, "device with ID %hu not in list\n", device_id);
	    exit(EXIT_FAILURE);
	}

	// open selected device
	device = nfc_open(context, devices[device_id]);
	if (!device) {
		fprintf(stderr, "cannot open nfc device\n");
	    exit(EXIT_FAILURE);
	}

	verb_print("using device #%hu: %s\n", device_id, nfc_device_get_name(device));

	return device;
}


FreefareTag poll_tag(nfc_device *device)
{
	FreefareTag *tags;
	FreefareTag tag;
	//nfc_target tag;
	char *tag_uid;
/*
	const nfc_modulation mod_mifare[1] = {
			{.nmt = NMT_ISO14443A,.nbr = NBR_106}
	};

	if (nfc_initiator_poll_target(device, mod_mifare, sizeof(mod_mifare) / sizeof(nfc_modulation), POLL_NUM, POLL_PERIOD, &tag) < 0) {
		nfc_perror(device, "nfc_initiator_poll_target");
		exit(EXIT_FAILURE);
	}

	ff_tag = freefare_tag_new(device, tag);
*/
	tags = freefare_get_tags(device);
	if (!tags || !tags[0]) {
		return NULL;
	}
	tag = tags[0];

	tag_uid = freefare_get_tag_uid(tag);
	// show tag UID
	verb_print("UID:  %s\n", tag_uid);
	
	// TODO find out what EV1 version and how much memory
	switch(freefare_get_tag_type(tag)) {
		case MIFARE_ULTRALIGHT_C:
			verb_print("Type: MF Ultralight C\n");
			break;
		case MIFARE_ULTRALIGHT:
			verb_print("Type: MF Ultralight\n");
			break;
		default:
			verb_print("Type: unsupported: %i\n", freefare_get_tag_type(tag));
			//return NULL;
	}

	if (mifare_ultralight_connect(tag) < 0) {
		fprintf(stderr, "error connecting to tag\n");
		return NULL;
	}

	return tag;
}



bool authenticate_tag(FreefareTag tag, uint8_t *custom_key)
{
	uint8_t default_key[16] = ULC_DEFAULT_KEY;
	MifareDESFireKey key;

	if (custom_key) {
		key = mifare_desfire_3des_key_new(custom_key);
	} else {
		key = mifare_desfire_3des_key_new(default_key);
	}

	if (mifare_ultralightc_authenticate(tag, key) != 0) {
		fprintf(stderr, "authentication failed\n");
		return false;
	}

	return true;
}

void read_tag(FreefareTag tag, signed short *page_range, char *file_name)
{
	MifareUltralightPage page;
	int page_num;
	int start_page;
	int end_page;
	FILE *fp;

	if (strcmp(file_name, "-") == 0) {
		fp = stdout;
	} else {
		fp = fopen(file_name, "w");
		if (!fp) {
			fprintf(stderr, "could not open file '%s'\n", file_name);
			return;
		}
	}
	
	start_page = page_range[0];
	end_page = page_range[1];
	page_num = start_page;

	verb_print("read pages...\n");
	while (page_num <= end_page && (mifare_ultralight_read(tag, page_num, &page)) == 0) {
		fwrite(page, 1, sizeof(page), fp);
		verb_print("%.2hu: %.2x %.2x %.2x %.2x\n", page_num, page[0], page[1], page[2], page[3]);
		page_num++;
	}
	verb_print("...done!\n");

	fclose(fp);
}

void write_tag(FreefareTag tag, signed short *page_range, char *file_name, bool override)
{
	MifareUltralightPage page;
	int page_num;
	int start_page;
	int end_page;
	FILE *fp;

	if (strcmp(file_name, "-") == 0) {
		fp = stdout;
	} else {
		fp = fopen(file_name, "rb");
		if (!fp) {
			fprintf(stderr, "could not open file '%s'\n", file_name);
			return;
		}
	}

	start_page = page_range[0];
	end_page = page_range[1];
	page_num = start_page;

	verb_print("write pages...\n");
	while (page_num <= end_page && fread(&page, sizeof(page), 1, fp) > 0) {
		verb_print("%.2hu: %.2x %.2x %.2x %.2x ", page_num, page[0], page[1], page[2], page[3]);

		if (page_num < 4 && !override) {
			verb_print("SKIPPED. Use override.\n")
		} else {
			if (mifare_ultralight_write(tag, page_num, page) >= 0) {
				verb_print("OK\n");
			} else {
				verb_print("FAILED\n");
			}
		}
		page_num++;
	}
	verb_print("...done!\n");

	fclose(fp);
}

void show_tag_info(FreefareTag tag) 
{
	MifareUltralightPage page;

	char *tag_uid = freefare_get_tag_uid(tag);
	verb_print("UID:        %s\n", tag_uid);

	verb_print("Lock bytes: ");
	if ((mifare_ultralight_read(tag, 2, &page)) == 0) {
		verb_print("%.2x %.2x ", page[2], page[3]);
		if ((mifare_ultralight_read(tag, 40, &page)) == 0) {
			verb_print("%.2x %.2x ", page[0], page[1]);
		}
		verb_print("\n");
	}
	

	verb_print("OTP:        ");
	if ((mifare_ultralight_read(tag, 3, &page)) == 0) {
		verb_print("%.2x %.2x %.2x %.2x ", page[0], page[1], page[2], page[3]);
	}
	printf("\n");

	verb_print("AUTH0:      ")
	if ((mifare_ultralight_read(tag, 42, &page)) == 0) {
		verb_print("%.2x", page[0]);
	}
	printf("\n");

	verb_print("AUTH1:      ")
	if ((mifare_ultralight_read(tag, 43, &page)) == 0) {
		verb_print("%.2x", page[0]);
	}
	printf("\n");


}

int usage(char *path)
{
	printf(BANNER);
	printf("%s [options]\n", path);
	printf(" -h          print this message\n");
	printf(" -i          print tag info\n");
	printf(" -r file     dump tag to file. Use \"-\" for stdout.\n");
	printf(" -w file     write to tag from file. Use \"-\" to read from stdin\n");
	printf(" -p range    read/write page range (e.g. 4:6 for pages 4 to 6. Default is all pages\n");
	printf(" -k key      use key for Ultralight C authentication. Format is: \"001122334455667788...\"\n");
	printf(" -d device   numerical device id. Default is 0\n");
	printf(" -l seconds  poll for tags every few seconds. Quit with ^C\n");
	printf(" -t          test for weaknesses:\n");
	printf(" -o          override mode to write to pages 00 to 03");
	printf("               - default key\n");
	printf("               - AUTH0/1 bytes not protected\n");
	


	return EXIT_SUCCESS;
}


int main(int argc, char **argv)
{
	char options[] = "hoiqr:w:k:p:i:d:l:t";
	int opt;
	unsigned short action = ACTION_NONE;
	signed short page_range[2] = {0, LAST_PAGE};
	char *key = NULL;
	uint8_t *custom_key = NULL;
	unsigned short device_id = 0;
	int poll_seconds = 0;
	nfc_device *device;
	FreefareTag tag;
	bool is_not_type_c = true;
	char *file_name;
	bool override = false;

	while( (opt = getopt(argc, argv, options)) != -1) {
		switch(opt) {
			case 'i':
				action = ACTION_INFO;
				break;
			case 'w':
				action = ACTION_WRITE;
				file_name = strdup(optarg);
				break;
			case 'r':
				action = ACTION_READ;
				file_name = strdup(optarg);
				break;
			case 'p':
				// TODO: check string format
				sscanf(optarg, "%hu:%hu", &(page_range[0]), &(page_range[1]));
				break;
			case 'k':
				key = strdup(optarg);
				custom_key = key;
				break;
			case 'q':
				quiet = true;
				break;
			case 'd':
				device_id = atoi(optarg);
				break;
			case 'o':
				override = true;
				break;
			case 'l':
				poll_seconds = atoi(optarg);
				break; 
			case 't':
				// TODO: test
			case 'h':
				// do nothing and fallthrough
			default:
				return usage(*argv);

		}
	}

	verb_print(BANNER);


	printf("%i %i\n", getuid(), geteuid());

	// connect to device
	device = connect_device(device_id);
	if (!device) {
		fprintf(stderr, "could not connect to device!\n");
	    exit(EXIT_FAILURE);
	}


	// drop privileges
	setregid(getgid(), getgid());
	setreuid(getuid(), getuid());

	printf("%i %i\n", getuid(), geteuid());
	
	// poll tag and perform action
	do {

		verb_print("waiting for tag...\n");
		tag = poll_tag(device);
		if (!tag) {
			continue;
		}
		verb_print("connected to tag\n", tag);

		if (!is_mifare_ultralight(tag) && !is_mifare_ultralightc(tag)) {
			verb_print("not an ultralight card\n");
			return 0;
		}


		// authenticate to tag
		if (is_mifare_ultralightc(tag)) {
			if (!custom_key) {
				verb_print("authenticating using default key\n");
			} else {
				verb_print("authenticating using key: %s\n", custom_key);
			}

			if (!authenticate_tag(tag, custom_key)) {
				verb_print("authentication failed. Your actions might fail as well.\n");
			} else {
				verb_print("authentication succeeded.\n");
			}

		}




		// perform action
		switch(action) {
			case ACTION_INFO:
				show_tag_info(tag);
				break;
			case ACTION_READ:
				read_tag(tag, page_range, file_name);
				break;
			case ACTION_WRITE:
				write_tag(tag, page_range, file_name, override);
				break;
		}
	} while (poll_seconds > 0 && sleep(poll_seconds) == 0);

	return EXIT_SUCCESS;
}
