/*
 * asn1.c
 *
 *  Created on: 17.03.2014
 *      Author: fth
 */

#include <string.h>
#include <assert.h>

#include "asn1.h"

/**
 * Decode the tag from an ASN.1 object and update the reference pointer
 *
 * Decode the tag value from the ASN.1 coded data object referenced by the parameter
 * Ref. One and two byte tag values are supported. See asn1Length() function call for
 * an example.
 *
 * @param Ref       Address of the pointer variable which points to the tag field of
 *                  the TLV structure. It gets updated by the function to point to the
 *                  length field.
 *
 * @return          The function returns the tag value for the ASN.1 data object.
 */
unsigned int asn1Tag(unsigned char **Ref)
{
	unsigned int rc;

	rc = *(*Ref)++;

	if ((rc & 0x01F) == 0x1F) {
		do	{
			rc = (rc << 8) + *(*Ref)++;
		} while (rc & 0x80);
	}

	return rc;
}

/**
 * Decode the length from an ASN.1 object and update the reference pointer.
 *
 * Decode the length value from the ASN.1 coded data object referenced by the pa-
 * rameter Ref. One, two and three byte length values are supported. A prior call of
 * asn1Tag() should have moved the pointer Ref to the length field of the TLV object.
 *
 * Note: Usually asn1Tag() and asn1Length() are used directly after another, even if the
 * length information is not of interest. But this is the only safe way to get to the data field,
 * because the tag and length fields may have a variable size.
 *
 * @param Ref       Address of the pointer variable which points to the length field
 *                  of the TLV structure. It gets updated by the function to point to
 *                  the value field.
 *
 * @return          The function returns the length value for the ASN.1 data object.
 *
 * Example: Decode an ASN.1 data object.
 *
 * \code
 * unsigned char ASN1[] = { 0x5F,0x10,0x02,0x20,0x30 };     // Tag=5F10, Length=2
 * unsigned char *po;
 * int  len;
 *
 * po = ASN1;
 * prnPrintf("Tag = %x\n", asn1Tag(&po));
 *
 * len = asn1Length(&po);
 * prnPrintf("Length = %d\n", len);
 *
 * prnPrintf("Value =");
 * while(len--)
 *     prnPrintf(" %02X", *po++);
 * \endcode
 */
int asn1Length(unsigned char **Ref)
{
	int l,c;

	l = *(*Ref)++;

	if (l & 0x80) {
		c = l & 0x7F;
		if (c == 0) {
			return -1;
		}
		l = 0;
		while(c--) {
			l = (l << 8) | *(*Ref)++;
		}
	}

	return l;
}

/**
 * Construct the ASN.1 tag at referenced memory position.
 *
 * Store the tag according to ASN.1 BER-TLV rules in the message buffer. The function
 * decides whether one or two byte storage is required.
 *
 * @param Ref       Address of the pointer variable which points to the tag field of
 *                  the TLV structure. It gets updated by the function to point to the
 *                  length field.
 * @param Tag       Tag that shall be stored at position Ref.
 *
 */
void asn1StoreTag(unsigned char **Ref, unsigned short Tag)
{
	if ((Tag & 0x1F00) == 0x1F00)
		*(*Ref)++ = Tag >> 8;
	*(*Ref)++ = Tag & 0xFF;
}

/**
 * Construct the ASN.1 length field at referenced memory position.
 *
 * Store the length according to ASN.1 BER-TLV rules in the message buffer. The func-
 * tion decides whether one, two or three byte of storage is required.
 *
 * @param Ref       Address of the pointer variable which points to the tag field of
 *                  the TLV structure. It gets updated by the function to point to the
 *                  value field.
 * @param Length    Value to be stored in the length field.
 */
void asn1StoreLength(unsigned char **Ref, int Length)
{
	if (Length >= 256) {
		*(*Ref)++ = 0x82;
		*(*Ref)++ = (unsigned char)(Length >> 8);
		*(*Ref)++ = (unsigned char)(Length & 0xFF);
	} else if (Length >= 128) {
		*(*Ref)++ = 0x81;
		*(*Ref)++ = (unsigned char)Length;
	} else
		*(*Ref)++ = (unsigned char)Length;
}

/**
 * Encapsulate the provided message in an ASN.1 TLV structure.
 *
 * This function combines the both functions asn1StoreTag() and asn1StoreLength() and
 * encapsulates the message provided in Msg with an ASN.1 TLV structure.
 *
 * WARNING: Tag and length field will be added to the beginning of the message. Please
 * make sure, that sufficient space is available in the message buffer (maximum 5 addi-
 * tional bytes).
 *
 * @param Tag       The tag that shall be given to the message
 * @param Msg       Pointer to the message buffer which contains the message to
 *                  be encapsulated. The tag and length fields will be added at the
 *                  beginning of this buffer.
 * @param MsgLen    Length of the given message in the Msg buffer
 * @return          The function will return the total number of bytes in the message
 *                  buffer. It is of cause now larger than MsgLen.
 */
int asn1Encap(unsigned short Tag, unsigned char *Msg, int MsgLen)
{
	unsigned char tmpbuf[6], *po;
	int len;

	po = tmpbuf;
	asn1StoreTag(&po, Tag);
	asn1StoreLength(&po, MsgLen);
	len = po - tmpbuf;

	memmove(Msg + len, Msg, MsgLen);
	memmove(Msg, tmpbuf, len);

	return MsgLen + len;
}

/**
 * Find the TLV object within a TLV structure
 *
 * Scan through the TLV structure an find the object referenced by the path argument.
 * The path argument is a concatenation of tag value which, starting with the outermost
 * tag, describes the full path to the object. The level parameter denotes the number of
 * tags in the path, aka the nested level within the structure.
 *
 * @param data      The TLV data structure
 * @param path      Path to the desired object (List of tags)
 * @param level     Number of tags in the path
 * @return          Pointer to the object or NULL
 *
 * Example:
 * \code
 * asn1Find("\x6F\x04\x40\x02\x12\x34", "\x6F\40", 2);
 * \endcode
 */
unsigned char *asn1Find(unsigned char *data, unsigned char *path, int level)
{
	int d, p, l, datalen;
	unsigned char *obj;

	obj = data;
	d = asn1Tag(&data);
	p = asn1Tag(&path);

	if (d != p)
		return NULL;

	level--;

	while (level) {
		data = obj;
		asn1Tag(&data);
		datalen = asn1Length(&data);
		p = asn1Tag(&path);

		do	{
			obj = data;
			d = asn1Tag(&data);
			l = asn1Length(&data);
			data += l;
			datalen -= data - obj;
		} while ((datalen > 0) && (p != d));

		if ((datalen <= 0) && (p != d))
			return NULL;

		level--;
	}

	return obj;
}

/**
 * Decode the next TLV object
 *
 * Decode the tag and length of the next TLV object and set the value pointer
 * accordingly. The pointer and remaining buffer length is updated by this call.
 *
 * @param ref       Pointer to pointer to first byte of next tag
 * @param reflen    Pointer to variable containing the remaining buffer length
 * @param tag       Pointer to variable updated with the tag value
 * @param length    Pointer to variable updated with the length value
 * @param value     Pointer to a pointer updated with the value field
 * @return          true if further object has been decoded
 */
int asn1Next(unsigned char **ref, int *reflen, int *tag, int *length, unsigned char **value)
{
	unsigned char *base;

	if (*reflen == 0) {
		return 0;
	}
	base = *ref;
	*tag = asn1Tag(ref);
	*length = asn1Length(ref);

	if ((*reflen == -1) && (*tag == 0)) {
		return 0;
	}

	*value = *ref;
	*ref += *length;
	*reflen -= *ref - base;

	return 1;
}

/**
 * Validate a TLV structure, traversing into nested objects recursively
 *
 * @param data the first tag byte
 * @param length the maximum length on the buffer
 * @return 0 if valid, offset with error otherwise
 */
int asn1Validate(unsigned char *data, size_t length)
{
	int ofs;
	int l, rc, tag, tl;
	unsigned char *po;

	if (length < 2) {		// Object must have at least two bytes
		return 1;
	}

	ofs = 0;				// Decode tag
	if ((*(data + ofs) & 0x1F) == 0x1F) {
		do	{				// Decode multi-byte tag
			ofs++;
			if ((ofs >= length) || (ofs > 4)) {
				return ofs;
			}
		} while (*(data + ofs) & 0x80);
	}
	ofs++;

	if (ofs >= length) {	// Length missing
		return ofs;
	}

	l = *(data + ofs);
	ofs++;

	if (l & 0x80) {			// Multi-byte length
		int c = l & 0x7F;
		if (c > 3) {		// No more than 3 byte in length indicator
			return ofs - 1;
		}
		if (c > 0) {		// Finite length
			l = 0;
		} else {			// Undetermined length
			l = -1;
		}
		while (c--) {
			if (ofs >= length) {
				return ofs;
			}
			l = (l << 8) | *(data + ofs);
			ofs++;
		}
	}

	if (ofs + l > length) {
		return length;
	}

	if (l == 0) {
		return 0;
	}

	if (*data & 0x20) {				// Traverse into constructed object
		while(1) {					// Process list of contained TLV objects
			po = data + ofs;

			rc = asn1Validate(po, l);
			if (rc != 0) {
				return ofs + rc;
			}

			tag = asn1Tag(&po);
			tl = asn1Length(&po);
			tl += po - (data + ofs);

			ofs += tl;

			if (l == -1) {
				if ((tag == 0) && (tl == 0)) {
					break;
				}
			} else {
				l -= tl;
				if (l <= 0) {
					break;
				}
			}
		}
	}
	return 0;
}

/**
 * Decode integer from value field encoded MSB first
 *
 * @param data the value field
 * @param length the length of the value field
 * @param value pointer to variable receiving the value
 */
int asn1DecodeInteger(unsigned char *data, size_t length, int *value)
{
	int c = sizeof(int);

	*value = 0;
	while ((c-- > 0) && (length > 0)) {
		*value = (*value << 8) | *data;
		data++;
		length--;
	}
	if (length > 0) {
		return -1;
	}
	return 0;
}

