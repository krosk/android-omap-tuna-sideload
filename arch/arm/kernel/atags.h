#ifdef CONFIG_ATAGS_PROC
extern void save_atags(struct tag *tags);
#else
#ifdef CONFIG_FAST_SWITCH
extern void save_atags(struct tag *tags);
#else
static inline void save_atags(struct tag *tags) { }
#endif
#endif
