#ifndef MODULE_EMULATOR_CONAX_H
#define MODULE_EMULATOR_CONAX_H

#ifdef WITH_EMU

int8_t conax_ecm(uint16_t caid, uint8_t *ecm, uint8_t *dw);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_CONAX_H
