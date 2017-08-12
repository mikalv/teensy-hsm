#ifndef __MACROS_H__
#define __MACROS_H__

#define WRITE64(dst, val) \
    {\
        *(dst)++ = (uint8_t) ((val) >> 56); \
        *(dst)++ = (uint8_t) ((val) >> 48); \
        *(dst)++ = (uint8_t) ((val) >> 40); \
        *(dst)++ = (uint8_t) ((val) >> 32); \
        *(dst)++ = (uint8_t) ((val) >> 24); \
        *(dst)++ = (uint8_t) ((val) >> 16); \
        *(dst)++ = (uint8_t) ((val) >> 8); \
        *(dst)++ = (uint8_t) ((val)); \
    }

#define WRITE32(dst, val) \
    {\
        *(dst)++ = (uint8_t) ((val) >> 24); \
        *(dst)++ = (uint8_t) ((val) >> 16); \
        *(dst)++ = (uint8_t) ((val) >> 8); \
        *(dst)++ = (uint8_t) ((val)); \
    }

#define READ32(p) (((p)[0] << 24) | ((p)[1] << 16) | ((p)[2] << 8) | (p)[3])
#define MEMSET(v) memset(&(v), 0, sizeof((v)))
#define MIN(a,b) ((a) > (b)) ? (b) : (a)
#endif
