#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

void cbd(poly *r, const uint8_t buf[KYBER_ETA*KYBER_N/4]);

#endif
