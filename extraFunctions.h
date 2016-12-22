/*
 * extraFunctions.h
 *
 *  Created on: Oct 15, 2013
 *      Author: Jacob Saunders
 *  This file contains methods for converting various standard data types
 *  useful for avoiding potential buffer overflows or other unexpected
 *  errors.
 */

#ifndef EXTRAFUNCTIONS_H_
#define EXTRAFUNCTIONS_H_

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

//For the method to convert strings to integers.
enum StrToIntError { SUCCESS, OVERFLOW, UNDERFLOW, INCONVERTIBLE };
enum StrToIntError strToInt(int *i, char const *string, int base);

#endif /* EXTRAFUNCTIONS_H_ */
