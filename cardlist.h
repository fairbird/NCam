#ifndef MODULE_CARDLIST_H_
#define MODULE_CARDLIST_H_

#ifdef WITH_CARDLIST
struct atrlist { char providername[32]; char atr[80]; char info[92]; };
void findatr(struct s_reader *reader);
extern struct atrlist current;
#endif // WITH_CARDLIST

#endif
