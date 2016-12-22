/*
 * typeConversion.c
 *
 *  Created on: Oct 15, 2013
 *      Author: Jacob Saunders
 *  This file contains methods for converting various standard data types
 *  useful for avoiding potential buffer overflows or other unexpected
 *  errors.
 */

#include "extraFunctions.h"

enum StrToIntError strToInt(int *i, char const *string, int base)
{
	char *end;
	long l;
	errno = 0;
	l = strtol(string, &end, base);
	if ((errno == ERANGE && l == LONG_MAX) || l > INT_MAX)
	{
		return OVERFLOW;
	}
	else if ((errno == ERANGE && l == LONG_MIN) || l < INT_MIN)
	{
		return UNDERFLOW;
	}
	if (*string == '\0' || *end != '\0')
	{
		return INCONVERTIBLE;
	}
	(*i) = (int)l;
	return SUCCESS;
}

