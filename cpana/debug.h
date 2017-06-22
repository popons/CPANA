/* $Id: debug.h,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#ifdef DEBUG

#define IFDEBUG(x) do { x; } while (0)
extern void dump(uint8_t *, size_t);

#else

#define IFDEBUG(x) do { } while (0)

#endif
