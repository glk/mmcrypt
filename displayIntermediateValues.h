/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by the designers,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _displayIntermediateValues_h_
#define _displayIntermediateValues_h_

#include <stdio.h>

#define displaySetIntermediateValueFile(f)		(void)0
#define displaySetLevel(level)				(void)0
#define displayBytes(level, text, bytes, size)		(void)0
#define displayBits(level, text, data, size, MSBfirst)	(void)0
#define displayStateAsBytes(level, text, state)		(void)0
#define displayStateAs32bitWords(level, text, state)	(void)0
#define displayStateAs64bitWords(level, text, state)	(void)0
#define displayRoundNumber(level, i)			(void)0
#define displayText(level, text)			(void)0

#endif
