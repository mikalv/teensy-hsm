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
        (dst)[0] = (uint8_t) ((val) >> 24); \
        (dst)[1] = (uint8_t) ((val) >> 16); \
        (dst)[2] = (uint8_t) ((val) >> 8); \
        (dst)[3] = (uint8_t) ((val)); \
    }

#define WRITE16(dst, val) \
    {\
        (dst)[0] = (uint8_t) ((val) >> 8); \
        (dst)[1] = (uint8_t) ((val)); \
    }

#define READ32(p) (((p)[0] << 24) | ((p)[1] << 16) | ((p)[2] << 8) | (p)[3])
#define READ16(p) (((p)[0] << 8) | (p)[1])
#define MEMCLR(v) memset(&(v), 0, sizeof((v)))
#define MIN(a,b) ((a) > (b)) ? (b) : (a)
#endif
