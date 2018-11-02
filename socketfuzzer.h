#include "honggfuzz.h"

bool fuzz_waitForExternalInput(run_t* run);

bool fuzz_prepareSocketFuzzer(run_t* run);
int fuzz_waitforSocketFuzzer(run_t* run);

bool fuzz_notifySocketFuzzerNewCov(honggfuzz_t* hfuzz);
bool fuzz_notifySocketFuzzerOldCov(honggfuzz_t* hfuzz);
bool fuzz_notifySocketFuzzerCrash(run_t* run);

bool setupSocketFuzzer(honggfuzz_t* hfuzz);
void cleanupSocketFuzzer();
typedef struct {
char buf[4];
uint64_t stats[3];
}ret_msg;
