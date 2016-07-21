#ifdef DEBUG
	#define printf(...) printf(__VA_ARGS__);
#else
	#define printf(...) (void)0;
#endif
