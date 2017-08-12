#ifndef __STORAGE_H__
#define __STORAGE_H__

#include <stdint.h>
#include "hardware.h"

class Storage {
    public:
        Storage();
        void load(uint8_t *key);
        void store(uint8_t *key);
        void clear();
    private:
        uint8_t buffer[EEPROM_SIZE];
}
#endif
