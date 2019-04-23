#include "honggfuzz.h"

bool fuzz_GetExternalInput(run_t* run);

bool fuzz_prepareGrammarFuzzer(run_t* run);
int fuzz_waitforGrammarFuzzer(run_t* run);

bool fuzz_notifyGrammarFuzzerCov(honggfuzz_t* , uint64_t, uint64_t, uint64_t, char *);
bool fuzz_notifyGrammarFuzzerCrash(run_t* run);

bool setupGrammarFuzzer(honggfuzz_t* hfuzz);
void cleanupGrammarFuzzer();
typedef struct {
        char  buf[4];
        uint64_t stats[3];
}cov_stats;
