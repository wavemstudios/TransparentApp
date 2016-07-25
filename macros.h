#ifndef MACROS_H_
#define MACROS_H_

//Macro for turning printf ON and OFF for debug uses DEBUG flag in Makefile
#ifdef DEBUG
	#define printf(...) printf(__VA_ARGS__);
#else
	#define printf(...) (void)0;
#endif

#endif /* MACROS_H_ */
