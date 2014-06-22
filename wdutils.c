/*
 * Copyright (c) 2013,2014 Dan Lukes 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/ioctl.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <err.h>
#include <getopt.h>
#include <assert.h>
#include <iconv.h>

#include <arpa/inet.h>
#include <termios.h>

#ifdef __FreeBSD__
#include <sha256.h>

#include <cam/scsi/scsi_message.h>
#include <camlib.h>

#define SCSI_DIR_IN CAM_DIR_IN
#define SCSI_DIR_OUT CAM_DIR_OUT

typedef struct cam_device scsi_device;
#endif


#ifndef max
#define max(a,b) ((a)>(b)?(a):(b))
#endif
#ifndef min
#define min(a,b) ((a)<(b)?(a):(b))
#endif

#ifdef __Linux__
#endif

static int	scsicmd(scsi_device *device, char *cdb, int cdb_len, u_int32_t flags, u_int8_t * data_ptr, ssize_t * data_bytes);

static		size_t
chconv(const char *fromcode, const char *tocode, const char *inbuf, size_t * insize,
       char *outbuf, size_t * outsize)
{

	size_t		cc;
	static iconv_t	cd = (iconv_t) (-1);

	cd = iconv_open(tocode, fromcode);
	if (cd == (iconv_t) (-1)) {
		return -1;
	}
	cc = iconv(cd, &inbuf, insize, &outbuf, outsize);
	iconv_close(cd);

	return cc;
}


static void
hexdump(const void *ptr, int length, const char *hdr)
{
	int i, j, k;
	int cols = 16;
	const unsigned char *cp;
	char delim = ' ';

	if (hdr != NULL)
		printf("%s\n", hdr);

	cp = ptr;
	for (i = 0; i < length; i+= cols) {

		printf("%04x  ", i);

		for (j = 0; j < cols; j++) {
			k = i + j;
			if (k < length)
				printf("%c%02x", delim, cp[k]);
			else
				printf("   ");
		}

		printf("  |");
		for (j = 0; j < cols; j++) {
			k = i + j;
			if (k >= length)
				printf(" ");
			else if (cp[k] >= ' ' && cp[k] <= '~')
				printf("%c", cp[k]);
			else
				printf(".");
		}
		printf("|");
		printf("\n");
	}
}


struct sHandyStoreDescr {
	int		isValid;
	int		LastHandyBlockAddress;
	int		BlockLength;
	short unsigned int reserved1;
	short unsigned int MaximumTransferLength;
};

static int
GetHandyStoreSize(scsi_device *device, struct sHandyStoreDescr *h)
{
	char		cdb       [] = {0xD5, 0x00,
		0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00};

	int		cc;
	static unsigned char sector[512];
	ssize_t		ssector = sizeof(sector);


	h->isValid = 0;
	cc = scsicmd(device, cdb, sizeof(cdb), SCSI_DIR_IN, sector, &ssector);
	if (h != NULL) {
		h->LastHandyBlockAddress = ntohl(*(uint32_t *) (sector + 0));
		h->BlockLength = ntohl(*(uint32_t *) (sector + 4));
		h->reserved1 = ntohs(*(uint16_t *) (sector + 8));
		h->MaximumTransferLength = ntohs(*(uint16_t *) (sector + 10));
		h->isValid = 1;
	}
	//hexdump(sector, ssector, NULL);

	return cc;
}

static int
ReadHandyStore(scsi_device *device, int page, unsigned char *sector, ssize_t * ssector)
{
	char		cdb       [] = {0xD8, 0x00,
		0x00, 0x00, 0x00, 0x0F,
	0x00, 0x00, 0x01, 0x00};

	int		cc;


	*(uint32_t *) (cdb + 2) = htonl(page);

	cc = scsicmd(device, cdb, sizeof(cdb), SCSI_DIR_IN, sector, ssector);

	return cc;
}

static unsigned char
HSBChecksum(unsigned char *sect)
{
	unsigned char	cl = 0;
	int		i;

	for (i = cl = 0; i < 510; i++) {
		cl += sect[i];
	};

	cl += sect[0]; // Some WD Utils count sect[0] twice, some not ...

	return (-cl) & 0xFF;
}


enum {
	HandStoreSecurityBlock = 1,
	HandStoreUserSettingBlock = 2
};

struct sHandyStoreB1 {
	uint8_t		isValid;
	uint8_t		Signature[4];
	uint8_t		reserved1[4];
	int		IterationCount;
	char		Salt      [2 * (4 + 1)];
	uint8_t		reserved2[4];
	char		hint      [2 * (101 + 1)];
	uint8_t		reserved3[285];
	uint8_t		checksum;

};

static int
ReadHandyStoreBlock1(scsi_device *device, struct sHandyStoreB1 *h)
{
	int		cc;
	const char	Signature[4] = {0x00, 0x01, 'D', 'W'};
	static unsigned char sector[512];
	ssize_t		ssector = sizeof(sector);


	cc = ReadHandyStore(device, HandStoreSecurityBlock, sector, &ssector);
	if (cc != 0)
		return cc;
	if (HSBChecksum(sector) != sector[511]) {
		warnx("Wrong HSB1 checksum");
		return 1;
	}
	if (memcmp(Signature, sector, 4) != 0) {
		warnx("Wrong HSB1 signature ");
		return 1;
	}
	if (h != NULL) {
		size_t		ol;

		memcpy(h->Signature, sector + 0, 4);
		memcpy(h->reserved1, sector + 4, 4);
		h->IterationCount = *(uint32_t *) (sector + 8);
		ol = sizeof(h->Salt);
		memcpy(h->Salt, sector + 12, 2 * 4);
		h->Salt[2 * 5] = h->Salt[2 * 5 + 1] = '\0';
		memcpy(h->reserved2, sector + 20, 4);
		memcpy(h->hint, sector + 24, 2 * 101);
		h->hint[2 * 101] = h->hint[2 * 101 + 1] = '\0';
		memcpy(h->reserved3, sector + 226, 285);
		h->checksum = sector[511];
	}
	//hexdump(sector, ssector, NULL);

	return cc;
}

static void
print_HDBlock1(FILE * fp, struct sHandyStoreB1 *h)
{
	char		out       [202];
	size_t		il     , ol, cc;

	if (h->isValid == 0)
		return;

	fprintf(fp, "IterationCount=%d\n", h->IterationCount);

	il = 2 * 4;
	ol = sizeof(out);
	memset(out, 0, sizeof(out));
	cc = chconv("UCS-2LE", "ASCII//IGNORE", h->Salt, &il, out, &ol);
	fprintf(fp, "Salt='%s'\n", out);

	il = 2 * 101;
	ol = sizeof(out);
	memset(out, 0, sizeof(out));
	cc = chconv("UCS-2LE", "ASCII//IGNORE", h->hint, &il, out, &ol);
	fprintf(fp, "Hint='%s'\n", out);
}




struct sHandyStoreB2 {
	uint8_t		isValid;
	uint8_t		Signature[4];
	uint8_t		reserved1[4];
	uint8_t		Label  [64];
	uint8_t		reserved[439];
	uint8_t		checksum;

};

static int
ReadHandyStoreBlock2(scsi_device *device, struct sHandyStoreB2 *h)
{
	int		cc;
	const char	Signature[4] = {0x00, 0x02, 'D', 'W'};
	static unsigned char sector[512];
	ssize_t		ssector = sizeof(sector);


	cc = ReadHandyStore(device, HandStoreUserSettingBlock, sector, &ssector);
	if (cc != 0)
		return cc;
	if (HSBChecksum(sector) != sector[511]) {
		warnx("Wrong HSB2 checksum");
		return 1;
	}
	if (memcmp(Signature, sector, 4) != 0) {
		warnx("Wrong HSB2 signature ");
		return 1;
	}
	if (h != NULL) {
		memcpy(h->Signature, sector + 0, 4);
		memcpy(h->reserved1, sector + 4, 4);
		memcpy(h->Label, sector + 8, 64);
		memcpy(h->reserved, sector + 72, 439);
		h->checksum = sector[511];
	}
	//hexdump(sector, ssector, NULL);

	return cc;
}

static void
print_HDBlock2(FILE * fp, struct sHandyStoreB2 *h)
{
	char		out       [32 + 1];
	size_t		il     , ol, cc;

	if (h->isValid == 0)
		return;

	il = 2 * 32;
	ol = sizeof(out);
	memset(out, 0, sizeof(out));
	cc = chconv("UCS-2LE", "ASCII//IGNORE", h->Label, &il, out, &ol);
	fprintf(fp, "Label='%s'\n", out);
}




struct sEncryptionStatus {
	uint8_t		isValid;
	uint8_t		Signature;
	uint8_t		reserved1[2];
	uint8_t		SecurityState;
	uint8_t		CurrentCipherID;
	uint8_t		reserved2;
	short int	PasswordLength;
	uint8_t		KeyResetEnabler[4];
	uint8_t		reserved3[3];
	uint8_t		NumberOfCiphers;
	uint8_t		CipherList[16];
};


static int
GetEncryptionStatus(scsi_device *device, struct sEncryptionStatus *e)
{
	char		cdb       [] = {0xC0, 0x45,
		0x00, 0x00, 0x00, 0x00,
		0x00,
		0x00, 0x30,
	0x00};

	int		cc;
	static unsigned char sector[512];
	ssize_t		ssector = sizeof(sector);


	e->isValid = 0;
	cc = scsicmd(device, cdb, sizeof(cdb), SCSI_DIR_IN, sector, &ssector);
	if (cc != 0)
		return cc;

	if (sector[0] != 0x45) {
		warnx("Wrong encryption status signature %X", (int)sector[0]);
		return 1;
	}
	if (e != NULL) {
		e->Signature = sector[0];
		e->reserved1[0] = sector[1];
		e->reserved1[1] = sector[2];
		e->SecurityState = sector[3];
		e->CurrentCipherID = sector[4];
		e->reserved2 = sector[5];
		e->PasswordLength = ntohs(*(uint16_t *) (sector + 6));
		memcpy(e->KeyResetEnabler, sector + 8, 4);
		memcpy(e->reserved3, sector + 12, 3);
		e->NumberOfCiphers = sector[15];
		memset(e->CipherList, 0, sizeof(e->CipherList));
		memcpy(e->CipherList, sector + 16, max(e->NumberOfCiphers, sizeof(e->CipherList)));
		e->isValid = 1;
	}
	//hexdump(sector, ssector, NULL);

	return cc;
}

static void
mkPasswordBlock(unsigned char *pwblock, char *Salt, int IterationCount, char *password, int passwordlen)
{
	SHA256_CTX	ctx;
	int		i;
	char		pw        [512];
	int		pwlen = 0;

	for (i = 0; i < 4; i++) {
		if (Salt[2 * i] == '\0' && Salt[2 * i + 1] == '\0') {
			break;
		}
		pw[2 * i] = Salt[2 * i];
		pw[2 * i + 1] = Salt[2 * i + 1];
	};
	pwlen = i;

	for (i = 0; i < passwordlen / 2; i++) {
		if (password[2 * i] == '\0' && password[2 * i + 1] == '\0') {
			break;
		}
		pw[2 * (i + pwlen)] = password[2 * i];
		pw[2 * (i + pwlen) + 1] = password[2 * i + 1];
	};
	pwlen += i;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, pw, 2 * pwlen);
	SHA256_Final(pwblock, &ctx);

	for (i = 1; i < IterationCount; i++) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, pwblock, 32);
		SHA256_Final(pwblock, &ctx);
	}

}

static int
Unlock(scsi_device *device, char *password, int passwordlen)
{
	struct sEncryptionStatus e = {.isValid = 0}, enew = {.isValid = 0};
	struct sHandyStoreB1 h = {.isValid = 0};
	unsigned char	pwblock[8 + 32];
	ssize_t		pwblen;

	char		cdb       [] = {0xC1, 0xE1,
		0x00, 0x00, 0x00, 0x00,
		0x00,
		0x00, 0x28,
	0x00};

	int		cc;

//	hexdump(password, passwordlen, "Password ");

	cc = GetEncryptionStatus(device, &e);
	if (e.SecurityState != 1 || password == NULL || passwordlen <= 0)
		return e.SecurityState;

	switch (e.CurrentCipherID) {
	case 0x10:
	case 0x12:
	case 0x18:
		pwblen = 16;
		break;
	case 0x20:
	case 0x22:
	case 0x28:
		pwblen = 32;
		break;
	case 0x30:
		pwblen = 32;
		break;
	default:
		warnx("Unsupported cipher 0x%02X", e.CurrentCipherID);
		return e.SecurityState;
	}
	cc = ReadHandyStoreBlock1(device, &h);

	memset(pwblock, 0, 8);
	mkPasswordBlock(pwblock + 8, h.Salt, h.IterationCount, password, passwordlen);

	pwblock[0 + 0] = 0x45;
	*((uint16_t *) (pwblock + 4 + 2)) = htons(pwblen);
	pwblen += 8;
	cdb[8] = pwblen;

//	hexdump(cdb, sizeof(cdb), "CDB ");
//	hexdump(pwblock, pwblen, "PWB ");

	cc = scsicmd(device, cdb, sizeof(cdb), SCSI_DIR_OUT, pwblock, &pwblen);
	//if (cc != 0)
		//return cc;

	cc = GetEncryptionStatus(device, &enew);
	//warnx("SecurityState %d->%d", e.SecurityState, enew.SecurityState);
	return enew.SecurityState;
}

static int
ChangePassword(scsi_device *device, char *oldpassword, int oldpasswordlen, char *newpassword, int newpasswordlen)
{
	struct sEncryptionStatus e = {.isValid = 0}, enew = {.isValid = 0};
	struct sHandyStoreB1 h = {.isValid = 0};
	unsigned char	pwblock[4 + 4 + 2 * (32)];
	ssize_t		pwblen;

	char		cdb       [] = {0xC1, 0xE2,
		0x00, 0x00, 0x00, 0x00,
		0x00,
		0x00, 0x48,
	0x00};

	int		cc;

	//hexdump(oldpassword, oldpasswordlen, "OldPassword ");
	//hexdump(newpassword, newpasswordlen, "NewPassword ");


	cc = GetEncryptionStatus(device, &e);
	if (1 == 0 && e.SecurityState != 0 && e.SecurityState != 2)
		return e.SecurityState;

	switch (e.CurrentCipherID) {
	case 0x10:
	case 0x12:
	case 0x18:
		pwblen = 16;
		break;
	case 0x20:
	case 0x22:
	case 0x28:
		pwblen = 32;
		break;
	case 0x30:
		pwblen = 32;
		break;
	default:
		warnx("Unsupported cipher 0x%02X", e.CurrentCipherID);
		return e.SecurityState;
	}
	if ((oldpassword == NULL || oldpasswordlen <= 0) && (newpassword == NULL || newpasswordlen <= 0)) {
		//No change, return current status
			return e.SecurityState;
	}
	cc = ReadHandyStoreBlock1(device, &h);

	memset(pwblock, 0, sizeof(pwblock));


	pwblock[0] = 0x45;
	*((uint16_t *) (pwblock + 4 + 2)) = htons(pwblen);
	if (oldpassword != NULL && oldpasswordlen > 0) {
		mkPasswordBlock(pwblock + 4 + 4, h.Salt, h.IterationCount, oldpassword, oldpasswordlen);
		pwblock[3] |= 0x10;
	}
	if (newpassword != NULL && newpasswordlen > 0) {
		mkPasswordBlock(pwblock + 4 + 4 + 32, h.Salt, h.IterationCount, newpassword, newpasswordlen);
		pwblock[3] |= 0x01;
	}
	if ((pwblock[3] & 0x11) == 0x11)
		pwblock[3] &= 0xEE;

	pwblen = 4 + 4 + 2 * pwblen;
	cdb[8] = pwblen;

//	hexdump(cdb, sizeof(cdb), "CDB ");
//	hexdump(pwblock, pwblen, "PWB ");

	cc = scsicmd(device, cdb, sizeof(cdb), SCSI_DIR_OUT, pwblock, &pwblen);
	//if (cc != 0)
		//return cc;

	cc = GetEncryptionStatus(device, &enew);
	//warnx("SecurityState %d->%d", e.SecurityState, enew.SecurityState);
	return enew.SecurityState;
}

static int
SecureErase(scsi_device *device, unsigned char CipherID)
{
	struct sEncryptionStatus e = {.isValid = 0}, enew = {.isValid = 0};
	struct sHandyStoreB1 h = {.isValid = 0};
	unsigned char	pwblock[4 + 4 + 32];
	ssize_t		pwblen;

	char		cdb       [] = {0xC1, 0xE3,
		0x00, 0x00, 0x00, 0x00,
		0x00,
		0x00, 0x28,
	0x00};

	int		cc;

	cc = GetEncryptionStatus(device, &e);
	if (e.isValid == 0) {
		warnx("Failed to get current EncryptionStatus");
		return -1;
	};

	if (CipherID == 0)
		CipherID = e.CurrentCipherID;

	memcpy(cdb + 2, e.KeyResetEnabler, 4);

	cc = ReadHandyStoreBlock1(device, &h);

	memset(pwblock, 0, sizeof(pwblock));

	pwblock[0 + 0] = 0x45;

	switch (CipherID) {
	case 0x10:
	case 0x12:
	case 0x18:
		pwblen = 16;
		pwblock[0 + 3] = 0x01;
		break;
	case 0x20:
	case 0x22:
	case 0x28:
		pwblen = 32;
		pwblock[0 + 3] = 0x01;
		break;
	case 0x30:
		pwblen = 0;
		pwblock[0 + 3] = 0x00;
		break;
	default:
		warnx("Unsupported cipher 0x%02X", CipherID);
		return e.SecurityState;
	}

	pwblock[4 + 0] = CipherID;
	//New Cipher ID
		* ((uint16_t *) (pwblock + 4 + 2)) = htons(pwblen * 8);

	arc4random_buf(pwblock + 4 + 4, pwblen);

	pwblen += 8;
	//add header length
		cdb[8] = pwblen;

//	hexdump(cdb, sizeof(cdb), "CDB ");
//	hexdump(pwblock, pwblen, "PWB ");

	cc = scsicmd(device, cdb, sizeof(cdb), SCSI_DIR_OUT, pwblock, &pwblen);
	//if (cc != 0)
		//return cc;

	cc = GetEncryptionStatus(device, &enew);
	//warnx("SecurityState %d->%d", e.SecurityState, enew.SecurityState);
	return enew.isValid == 0 ? -1 : enew.SecurityState;
}

static int
StrtocID(char *n)
{
	if (n == NULL)
		return -1;
	if (strcmp(n, "AES_128_ECB") == 0)
		return 0x10;
	else if (strcmp(n, "AES_128_CBC") == 0)
		return 0x12;
	else if (strcmp(n, "AES_128_XTS") == 0)
		return 0x18;
	else if (strcmp(n, "AES_256_ECB") == 0)
		return 0x20;
	else if (strcmp(n, "AES_256_CBC") == 0)
		return 0x22;
	else if (strcmp(n, "AES_256_XTS") == 0)
		return 0x28;
	else if (strcmp(n, "FDE") == 0)
		return 0x30;
	else
		return -1;
}
static char    *
cIDtoStr(int CipherID)
{
	switch (CipherID) {
	case 0x10:
		return "AES_128_ECB";
	case 0x12:
		return "AES_128_CBC";
	case 0x18:
		return "AES_128_XTS";
	case 0x20:
		return "AES_256_ECB";
	case 0x22:
		return "AES_256_CBC";
	case 0x28:
		return "AES_256_XTS";
	case 0x30:
		return "FDE";
	default:
		return "unknown";
	}
}

static char    *
eIDtoStr(int SecurityStatus)
{
	switch (SecurityStatus) {
	case 0x00:
		return "No lock";
	case 0x01:
		return "Locked";
	case 0x02:
		return "Unlocked";
	case 0x06:
		return "Locked, unlock blocked";
	case 0x07:
		return "No keys";
	default:
		return "unknown";
	}
}

static void
print_EncryptionStatus(FILE * fp, struct sEncryptionStatus *e)
{
	int		i;

	if (e->isValid == 0)
		return;

	fprintf(fp, "SecurityState=%d (%s), CurrentCipherID=%02X (%s)\n",
		(int)e->SecurityState, eIDtoStr((int)e->SecurityState), (int)e->CurrentCipherID, cIDtoStr((int)e->CurrentCipherID));
	fprintf(fp, "PasswordLength = %d\n",
		(int)e->PasswordLength);
	fprintf(fp, "KeyResetEnabler = %02X %02X %02X %02X\n",
		(int)e->KeyResetEnabler[0], (int)e->KeyResetEnabler[1], (int)e->KeyResetEnabler[2], (int)e->KeyResetEnabler[3]);
	fprintf(fp, "%d supported ciphers:", e->NumberOfCiphers);
	for (i = 0; i < e->NumberOfCiphers; i++)
		fprintf(fp, " %02X (%s)", (int)e->CipherList[i], cIDtoStr((int)e->CipherList[i]));
	fprintf(fp, "\n");
}

static int
ModeSense(scsi_device *device, unsigned char PageCode, unsigned char SubpageCode, unsigned char PageControl, int dbd, unsigned char *data, unsigned char *datalen)
{
	ssize_t		dlen;

	char		cdb       [] = {0x1A, 0x00, 0x00, 0x00, 0x00, 0x00};

	int		cc;
	unsigned char  *mp;
	ssize_t		mlen;


	if (dbd != 0)
		cdb[1] |= 0x10;

	cdb[2] = ((PageControl & 0x03) << 6) | (PageCode & 0x3F);
	cdb[3] = SubpageCode;
	dlen = cdb[4] = *datalen;

	//hexdump(cdb, sizeof(cdb), "CDB ");

	*datalen = 0;
	cc = scsicmd(device, cdb, sizeof(cdb), SCSI_DIR_IN, data, &dlen);
	if (cc != 0)
		return cc;

	dlen = data[0] + 1;

//	hexdump(data, dlen, "MSR ");

	mp = data + 4 + data[3];
	mlen = dlen - 4 - data[3];

	memcpy(data, mp, mlen);
	*datalen = mlen;


	//hexdump(data, *datalen, "MSE ");


	return cc;
}

enum {
	kPOWERCONDITIONPAGE = 0x1A,
	kMODEDEVICECONFIGURATIONPAGE = 0x20,
	kMODEOPERATIONSPAGE = 0x21
};

enum {
	kMODE_SENSE_CURRENT_VALUES = 0x00,
	kMODE_SENSE_CHANGEABLE_VALUES = 0x01,
	kMODE_SENSE_DEFAULT_VALUES = 0x02,
	kMODE_SENSE_SAVED_VALUES = 0x03
};


#define UInt8 unsigned int
struct sDeviceConfigurationPage {
	UInt8		pageCode:6;
	UInt8		reserved1:1;
	UInt8		ParamSavable:1;

	UInt8		pageLength:8;

	UInt8		signature:8;
	UInt8		reserved2:8;

	UInt8		DisableSES:1;
	UInt8		DisableCDROM:1;
	UInt8		reserved3:5;
	UInt8		DisableAP:1;

	UInt8		DisableWhiteList:1;
	UInt8		TwoTBLimit:1;
	UInt8		reserved4:6;

	UInt8		reserved5:8;
	UInt8		reserved6:8;
};

static inline char *
btos(int b)
{
	return (b & 0x01) == 0 ? "false" : "true";
};

static inline char *
btof(int b)
{
	return (b & 0x01) == 0 ? "ro" : "rw";
};

static int
GetDeviceConfigurationPage(scsi_device *device, struct sDeviceConfigurationPage *sdcp, struct sDeviceConfigurationPage *s2)
{
	unsigned char	data[127];
	unsigned char	datalen = sizeof(data);
	int		cc1       , cc2;

	cc1 = ModeSense(device, kMODEDEVICECONFIGURATIONPAGE, 0, kMODE_SENSE_CURRENT_VALUES, 1, data, &datalen);
	memset(sdcp, 0, sizeof(*sdcp));
	memcpy(sdcp, data, min(datalen, sizeof(*sdcp)));

	if (s2 != NULL) {
		datalen = sizeof(data);
		cc2 = ModeSense(device, kMODEDEVICECONFIGURATIONPAGE, 0, kMODE_SENSE_CHANGEABLE_VALUES, 1, data, &datalen);
		memset(s2, 0, sizeof(*s2));
		memcpy(s2, data, min(datalen, sizeof(*s2)));
	}
	return cc1;
};

static void
print_SDCP(FILE * fp, struct sDeviceConfigurationPage *s, struct sDeviceConfigurationPage *r)
{
	fprintf(fp, "-- MODE PAGE 0x%02X, length=%d\n",
		(int)s->pageCode, (int)s->pageLength);
	fprintf(fp, "ParamSavable = %s\n", btos(s->ParamSavable));
	if (r->reserved1 != 0)
		fprintf(fp, "reserved1 = %s (%s)\n", btos(s->reserved1), btos(r->reserved1));
	fprintf(fp, "Signature=0x%02X (&0x%02X)\n", (int)s->signature, (int)r->signature);
	if (r->reserved2 != 0)
		fprintf(fp, "reserved2 = 0x%02X (&0x%02X)\n", (int)(s->reserved2), (int)(r->reserved2));
	fprintf(fp, "DisableAP = %s (%s)\n", btos(s->DisableAP), btof(r->DisableAP));
	fprintf(fp, "DisableCDROM = %s (%s)\n", btos(s->DisableCDROM), btof(r->DisableCDROM));
	if (r->reserved3 != 0)
		fprintf(fp, "reserved3 = 0x%02X (&0x%02X)\n", (int)(s->reserved3), (int)(r->reserved3));
	fprintf(fp, "DisableSES = %s (%s)\n", btos(s->DisableSES), btof(r->DisableSES));
	fprintf(fp, "TwoTBLimit = %s (%s)\n", btos(s->TwoTBLimit), btof(r->TwoTBLimit));
	fprintf(fp, "DisableWhiteList = %s (%s)\n", btos(s->DisableWhiteList), btof(r->DisableWhiteList));
	if (r->reserved4 != 0)
		fprintf(fp, "reserved4 = 0x%02X (&0x%02X)\n", (int)(s->reserved4), (int)(r->reserved4));
	if (r->reserved5 != 0)
		fprintf(fp, "reserved5 = 0x%02X (&0x%02X)\n", (int)(s->reserved5), (int)(r->reserved5));
	if (r->reserved6 != 0)
		fprintf(fp, "reserved6 = 0x%02X (&0x%02X)\n", (int)(s->reserved6), (int)(r->reserved6));
	fprintf(fp, "\n");
};

struct sOperationsPage {
	UInt8		pageCode:6;
	UInt8		reserved1:1;
	UInt8		ParamSavable:1;

	UInt8		pageLength:8;

	UInt8		signature:8;
	UInt8		reserved2:8;

	UInt8		eSATA15:	1;
	UInt8		LooseSB2:1;
	UInt8		reserved3:6;

	UInt8		enableCDEject:1;
	UInt8		CDMediaValid:1;
	UInt8		reserved4:6;

	UInt8		reserved5:8;
	UInt8		reserved6:8;
	UInt8		powerLEDBrite:8;
	UInt8		backlightBrite:8;

	UInt8		whiteOnBlack:1;
	UInt8		reserved7:7;

	UInt8		reserved8:8;

};

static int
GetOperationsPage(scsi_device *device, struct sOperationsPage *ocp, struct sOperationsPage *o2)
{
	unsigned char	data[127];
	unsigned char	datalen = sizeof(data);
	int		cc1       , cc2;

	cc1 = ModeSense(device, kMODEOPERATIONSPAGE, 0, kMODE_SENSE_CURRENT_VALUES, 1, data, &datalen);
	memset(ocp, 0, sizeof(*ocp));
	memcpy(ocp, data, min(datalen, sizeof(*ocp)));

	if (o2 != NULL) {
		datalen = sizeof(data);
		cc2 = ModeSense(device, kMODEOPERATIONSPAGE, 0, kMODE_SENSE_CHANGEABLE_VALUES, 1, data, &datalen);
		memset(o2, 0, sizeof(*o2));
		memcpy(o2, data, min(datalen, sizeof(*o2)));
	}
	return cc1;
};

static void
print_OCP(FILE * fp, struct sOperationsPage *s, struct sOperationsPage *r)
{
	fprintf(fp, "-- MODE PAGE 0x%02X, length=%d\n",
		(int)s->pageCode, (int)s->pageLength);
	fprintf(fp, "ParamSavable = %s\n", btos(s->ParamSavable));
	if (r->reserved1 != 0)
		fprintf(fp, "reserved1 = %s (%s)\n", btos(s->reserved1), btos(r->reserved1));
	fprintf(fp, "Signature=0x%02X (&0x%02X)\n", (int)s->signature, (int)r->signature);
	if (r->reserved2 != 0)
		fprintf(fp, "reserved2 = 0x%02X (&0x%02X)\n", (int)(s->reserved2), (int)(r->reserved2));
	fprintf(fp, "eSATA = %s (%s)\n", btos(s->eSATA15), btof(r->eSATA15));
	fprintf(fp, "LooseSB2 = %s (%s)\n", btos(s->LooseSB2), btof(r->LooseSB2));
	if (r->reserved3 != 0)
		fprintf(fp, "reserved3 = 0x%02X (&0x%02X)\n", (int)(s->reserved3), (int)(r->reserved3));
	fprintf(fp, "enableCDEject = %s (%s)\n", btos(s->enableCDEject), btof(r->enableCDEject));
	fprintf(fp, "CDMediaValid = %s (%s)\n", btos(s->CDMediaValid), btof(r->CDMediaValid));
	if (r->reserved4 != 0)
		fprintf(fp, "reserved4 = 0x%02X (&0x%02X)\n", (int)(s->reserved4), (int)(r->reserved4));
	fprintf(fp, "powerLEDBrite = 0x%02X (%s)\n", (int)(s->powerLEDBrite), btof(r->powerLEDBrite));
	fprintf(fp, "backlightBrite = 0x%02X (%s)\n", (int)(s->backlightBrite), btof(r->backlightBrite));
	if (r->reserved5 != 0)
		fprintf(fp, "reserved5 = 0x%02X (&0x%02X)\n", (int)(s->reserved5), (int)(r->reserved5));
	if (r->reserved6 != 0)
		fprintf(fp, "reserved6 = 0x%02X (&0x%02X)\n", (int)(s->reserved6), (int)(r->reserved6));
	fprintf(fp, "whiteOnBlack = %s (%s)\n", btos(s->whiteOnBlack), btof(r->whiteOnBlack));
	if (r->reserved7 != 0)
		fprintf(fp, "reserved7 = 0x%02X (&0x%02X)\n", (int)(s->reserved7), (int)(r->reserved7));
	if (r->reserved8 != 0)
		fprintf(fp, "reserved8 = 0x%02X (&0x%02X)\n", (int)(s->reserved8), (int)(r->reserved8));
	fprintf(fp, "\n");
};

#ifdef __FreeBSD__
static
int
scsicmd(scsi_device *device, char *cdb, int cdb_len, u_int32_t flags, u_int8_t * data_ptr, ssize_t * data_bytes)
{
	union ccb      *ccb;
	int		error = 0;
	int		retval;
	int		retry_count = 0;
	int		timeout = 5000;

	ccb = cam_getccb(device);

	if (ccb == NULL) {
		warnx("scsicmd: error allocating ccb");
		return (1);
	}
	bzero(&(&ccb->ccb_h)[1],
	      sizeof(union ccb) - sizeof(struct ccb_hdr));


	if (retry_count > 0)
		flags |= CAM_PASS_ERR_RECOVER;

	/* Disable freezing the device queue */
	flags |= CAM_DEV_QFRZDIS;

	/*
	 * We should probably use csio_build_visit or something like that
	 * here, but it's easier to encode arguments as you go. The
	 * alternative would be skipping the CDB argument and then encoding
	 * it here, since we've got the data buffer argument by now.
	 */
	bcopy(cdb, &ccb->csio.cdb_io.cdb_bytes, cdb_len);

	cam_fill_csio(&ccb->csio,
		       /* retries */ retry_count,
		       /* cbfcnp */ NULL,
		       /* flags */ flags,
		       /* tag_action */ MSG_SIMPLE_Q_TAG,
		       /* data_ptr */ data_ptr,
		       /* dxfer_len */ *data_bytes,
		       /* sense_len */ SSD_FULL_SIZE,
		       /* cdb_len */ cdb_len,
		       /* timeout */ timeout ? timeout : 5000);

	if (((retval = cam_send_ccb(device, ccb)) < 0)
	    || ((ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP)) {
		const char	warnstr[] = "error sending command";

		if (retval < 0)
			warn(warnstr);
		else
			warnx(warnstr);

		cam_error_print(device, ccb, CAM_ESF_ALL,
				CAM_EPF_ALL, stderr);
		error = 1;
		goto scsicmd_bailout;
	}
scsicmd_bailout:

	cam_freeccb(ccb);
	return (error);
}

#endif

static
void 
usage(char *p)
{
	warnx("%s dump <devname>", p);
	warnx("%s unlock <devname>", p);
	warnx("%s set <devname>", p);
	warnx("%s erase <devname> [CipherName]", p);
	warnx("%s readhsb <devname> block#", p);
}

static char *
fgets_noecho(char * restrict str, int size, FILE * restrict stream) {
	struct termios tattr;
	tcflag_t lflag;
	char *ret;
	int fd;
	
	fd = fileno(stdin);
	if (tcgetattr(fd, &tattr) != 0) {
		warn("tcgetattr(): %m");
		return (NULL);
	}
	lflag = tattr.c_lflag;
	tattr.c_lflag &= ~ECHO;
	if (tcsetattr(fd, TCSAFLUSH, &tattr) != 0) {
		warn("tcsetattr(): %m");
		return (NULL);
	}
	ret = fgets(str, size, stream);
	tattr.c_lflag = lflag;
	(void)tcsetattr(fd, TCSANOW, &tattr);
	if (ret != NULL)
		fputs("\n", stdout);
	return (ret);
}

int
main(int argc, char *argv[])
{
	char           *device = NULL;
	int		unit = 0;
	scsi_device *cam_dev = NULL;
	int		error = 0;

	char		name      [30];

	//printf("sizeof wchar_t = %d\n", sizeof(wchar_t));
	//assert(sizeof(wchar_t) == 2);

	if (argc < 3) {
		usage(argv[0]);
		goto done;
	};

#ifdef __FreeBSD__
	if (cam_get_device(argv[2], name, sizeof name, &unit)
	    == -1)
		errx(1, "%s", cam_errbuf);
	device = strdup(name);


	if ((cam_dev = cam_open_spec_device(device, unit, O_RDWR, NULL))
	    == NULL)
		errx(1, "%s", cam_errbuf);
#else
#error Function needs to be implemented
#endif
	struct sEncryptionStatus e = {.isValid = 0};
	error = GetEncryptionStatus(cam_dev, &e);

	if (strcmp(argv[1], "dump") == 0) {
		struct sHandyStoreDescr h = {.isValid = 0};
		error = GetHandyStoreSize(cam_dev, &h);
		warnx("Handy Store size %d blocks * %dB (max transfer size %d block)",
		      h.LastHandyBlockAddress + 1, h.BlockLength, h.MaximumTransferLength);

		print_EncryptionStatus(stderr, &e);

		struct sHandyStoreB1 hb1 = {.isValid = 0};
		error = ReadHandyStoreBlock1(cam_dev, &hb1);
		print_HDBlock1(stderr, &hb1);

		struct sHandyStoreB2 hb2 = {.isValid = 0};
		error = ReadHandyStoreBlock2(cam_dev, &hb2);
		print_HDBlock2(stderr, &hb2);

		struct sDeviceConfigurationPage sdcp, sr;
		error = GetDeviceConfigurationPage(cam_dev, &sdcp, &sr);
		if (error != 0)
			warnx("GetDeviceConfigurationPage cc = 0x%02X", error);
		else
			print_SDCP(stderr, &sdcp, &sr);

		struct sOperationsPage ocp, or;
		error = GetOperationsPage(cam_dev, &ocp, &or);
		if (error != 0)
			warnx("GetOperationsPage cc = 0x%02X", error);
		else
			print_OCP(stderr, &ocp, &or);

	} else if (strcmp(argv[1], "unlock") == 0) {
		if (e.SecurityState != 0x01) {
			warnx("SecurityState %02X (%s) not compatible with unlock.", e.SecurityState, eIDtoStr(e.SecurityState));
			goto done;
		}
		char		pwd       [512];
		char		opw       [512];
		size_t		ps     , il, ol, cc;

		fputs("Enter device password: ", stdout);
		fgets_noecho(pwd, sizeof(pwd) - 1, stdin);


		ps = strlen(pwd);
		if (ps >= 2 && pwd[ps - 2] == '\r' && pwd[ps - 1] == '\n') {
			pwd[ps -= 2] = '\0';
		} else if (ps >= 1 && pwd[ps - 1] == '\n') {
			pwd[ps -= 1] = '\0';
		}
		il = ps;
		ol = sizeof(opw);

		cc = chconv("ASCII", "UCS-2LE", pwd, &il, opw, &ol);
		error = Unlock(cam_dev, opw, 2 * ps);
		warnx("Device status: %02X (%s)", error, eIDtoStr((int)error));
		e.SecurityState = error;
		goto done;

	} else if (strcmp(argv[1], "set") == 0) {
		if (e.SecurityState != 0x00 && e.SecurityState != 0x02) {
			warnx("SecurityState %02X (%s) not compatible with unlock.", e.SecurityState, eIDtoStr(e.SecurityState));
			goto done;
		}
		char		oldpwd    [512];
		char		newpwd    [512];
		char		newpwd2   [512];
		char		oldopw    [512];
		char		newopw    [512];
		size_t		oldps  , newps, il, ol, cc;

		fputs("Enter old device password: ", stdout);
		fgets_noecho(oldpwd, sizeof(oldpwd) - 1, stdin);
		fputs("Enter new device password: ", stdout);
		fgets_noecho(newpwd, sizeof(newpwd) - 1, stdin);
		fputs("Repeat new password: ", stdout);
		fgets_noecho(newpwd2, sizeof(newpwd2) - 1, stdin);

		if (strcmp(newpwd, newpwd2) != 0) {
			warnx("Not same");
			return 1;
		};

		oldps = strlen(oldpwd);
		if (oldps >= 2 && oldpwd[oldps - 2] == '\r' && oldpwd[oldps - 1] == '\n') {
			oldpwd[oldps -= 2] = '\0';
		} else if (oldps >= 1 && oldpwd[oldps - 1] == '\n') {
			oldpwd[oldps -= 1] = '\0';
		}
		il = oldps;
		ol = sizeof(oldopw);

		cc = chconv("ASCII", "UCS-2LE", oldpwd, &il, oldopw, &ol);

		newps = strlen(newpwd);
		if (newps >= 2 && newpwd[newps - 2] == '\r' && newpwd[newps - 1] == '\n') {
			newpwd[newps -= 2] = '\0';
		} else if (newps >= 1 && newpwd[newps - 1] == '\n') {
			newpwd[newps -= 1] = '\0';
		}
		il = newps;
		ol = sizeof(newopw);

		cc = chconv("ASCII", "UCS-2LE", newpwd, &il, newopw, &ol);

		error = ChangePassword(cam_dev, oldopw, 2 * oldps, newopw, 2 * newps);
		warnx("Device status: %02X (%s)", error, eIDtoStr((int)error));
	} else if (strcmp(argv[1], "erase") == 0) {
		char		ask       [512];
		char		newpwd    [512];
		char		newpwd2   [512];
		char		newopw    [512];
		size_t		newps = 0;
		size_t		il     , ol, cc;
		int		CipherID = -1;

		if (argc < 4)
			CipherID = 0;
		else {
			CipherID = StrtocID(argv[3]);
			if (CipherID == -1) {
				warnx("Unknown cipher '%s'", argv[3]);
				goto done;
			}
		}
		fputs("Do you want secure erase ? (write 'YES!'): ", stdout);
		fgets(ask, sizeof(ask) - 1, stdin);
		if (strcmp(ask, "YES!\n") == 0) {

			fputs("Enter new device password: ", stdout);
			fgets_noecho(newpwd, sizeof(newpwd) - 1, stdin);
			fputs("Repeat new password: ", stdout);
			fgets_noecho(newpwd2, sizeof(newpwd2) - 1, stdin);

			if (strcmp(newpwd, newpwd2) != 0) {
				warnx("Not same");
				return 1;
			};

			newps = strlen(newpwd);
			if (newps >= 2 && newpwd[newps - 2] == '\r' && newpwd[newps - 1] == '\n') {
				newpwd[newps -= 2] = '\0';
			} else if (newps >= 1 && newpwd[newps - 1] == '\n') {
				newpwd[newps -= 1] = '\0';
			}
			il = newps;
			ol = sizeof(newopw);

			cc = chconv("ASCII", "UCS-2LE", newpwd, &il, newopw, &ol);

			error = SecureErase(cam_dev, CipherID);
			warnx("Device status: %02X (%s)", error, eIDtoStr((int)error));
		}
	} else if (strcmp(argv[1], "readhsb") == 0) {
		long int	bnumber = -1;
		static unsigned char sector[512];
		ssize_t		ssector = sizeof(sector);

		if (argc < 4) {
			usage(argv[0]);
			goto done;
		} else {
			bnumber = atol(argv[3]);
		}


		error = ReadHandyStore(cam_dev, bnumber, sector, &ssector);
		if (error != 0) {
			goto done;
		}
		warnx("Handy store block %ld:", bnumber);
		hexdump(sector, ssector, NULL);
	} else {
		usage(argv[0]);
	}

done:
	if (cam_dev != NULL)
#ifdef __FreeBSD__
		cam_close_device(cam_dev)
#else
#error Function needs to be implemented
#endif
		;

	exit(error);
}
