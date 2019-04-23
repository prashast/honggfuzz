#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "input.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/ns.h"
#include "libhfcommon/util.h"

#include "grammarfuzzer.h"

bool fuzz_GetExternalInput(run_t* run) {
    /* tell the external fuzzer to do his thing */
    if (!fuzz_prepareGrammarFuzzer(run)) {
        LOG_F("fuzz_prepareGrammarFuzzer() failed");
    }

    /* the external fuzzer may inform us of a crash */
    int result = fuzz_waitforGrammarFuzzer(run);
    if (result == 2) {
        return false;
    }

    return true;
}

bool fuzz_prepareGrammarFuzzer(run_t* run) {
    // Notify fuzzer that he should send teh things
    LOG_D("fuzz_prepareGrammarFuzzer: SEND Fuzz");
    cov_stats *cov_buf = (cov_stats *)malloc(sizeof(cov_stats));
    strncpy(cov_buf->buf, "Fuzz", 4);

    cov_buf->stats[0] = 0L ;
    cov_buf->stats[1] = 0L;
    cov_buf->stats[2] = 0L;
    return files_sendToSocket(
        run->global->grammarFuzzer.clientSocket, (uint8_t *)cov_buf, sizeof(cov_stats));
}

int fuzz_waitforGrammarFuzzer(run_t* run) {
    // Create a buffer equal to max input size 
    ssize_t ret;
    size_t inp_size;
    uint8_t buf[run->global->mutate.maxFileSz];

    // Retrieve the input from the external input generator and put in buf 
    bzero(buf, run->global->mutate.maxFileSz);
    ret = files_readFromFd(run->global->grammarFuzzer.clientSocket, buf, 
                    run->global->mutate.maxFileSz);
    inp_size = strlen((const char *)buf);
    // Set the size of the input to be sent
    input_setSize(run, inp_size);
    memcpy(run->dynamicFile, buf, inp_size);

    LOG_D("fuzz_waitforGrammarFuzzer: RECV: %s Size:%zu", buf, inp_size);

    // We dont care what we receive, its just to block here
    if (ret < 0) {
        LOG_F("fuzz_waitforGrammarFuzzer: received: %zu", ret);
        return 2;
    }

    return 0;
}

bool fuzz_notifyGrammarFuzzerCov(honggfuzz_t* hfuzz, uint64_t softCntPc, uint64_t softCntEdge,
                uint64_t softCntCmp, char *mode) {
    cov_stats *cov_buf = (cov_stats *)malloc(sizeof(cov_stats));
    strncpy(cov_buf->buf, mode, 4);

    if (!strncmp(cov_buf->buf, "New!", 4)) { 
        LOG_D("fuzz_notifyGrammarFuzzer: SEND: New!");
    }
    else {
        LOG_D("fuzz_notifyGrammarFuzzer: SEND: Old!");
    }
    
    cov_buf->stats[0] = softCntPc;
    cov_buf->stats[1] = softCntEdge;
    cov_buf->stats[2] = softCntCmp;
    // Tell the fuzzer that the thing he sent reached new BB's
    LOG_D("Struct size:%zu Socket%d", sizeof(cov_stats), hfuzz->grammarFuzzer.clientSocket)
    bool ret = files_sendToSocket(hfuzz->grammarFuzzer.clientSocket, (uint8_t*)cov_buf, sizeof(cov_stats));
    if (!ret) {
        LOG_F("fuzz_notifyGrammarFuzzerCov failed");
    }

    return ret;
}

bool fuzz_notifyGrammarFuzzerCrash(run_t* run) {
    bool ret = files_sendToSocket(run->global->grammarFuzzer.clientSocket, (uint8_t*)"Cras", 4);
    LOG_D("fuzz_notifySocketFuzzer: SEND: Crash");
    if (!ret) {
        LOG_F("fuzz_notifyGrammarFuzzer");
    }

    return true;
}

bool setupGrammarFuzzer(honggfuzz_t* run) {
    int s, len;
    socklen_t t;
    struct sockaddr_un local, remote;
    char socketPath[512];
    snprintf(socketPath, sizeof(socketPath), "/tmp/honggfuzz_socket.%i", getpid());

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return false;
    }

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, socketPath);
    unlink(local.sun_path);
    len = strlen(local.sun_path) + sizeof(local.sun_family);
    if (bind(s, (struct sockaddr*)&local, len) == -1) {
        perror("bind");
        return false;
    }

    if (listen(s, 5) == -1) {
        perror("listen");
        return false;
    }

    printf("Waiting for GrammarFuzzer connection on socket: %s\n", socketPath);
    t = sizeof(remote);
    if ((run->grammarFuzzer.clientSocket =
                TEMP_FAILURE_RETRY(accept(s, (struct sockaddr*)&remote, &t))) == -1) {
        perror("accept");
        return false;
    }

    run->grammarFuzzer.serverSocket = s;
    printf("A GrammarFuzzer client connected. Continuing.\n");
    LOG_D("Client socket:%d", run->grammarFuzzer.clientSocket);

    return true;
}

void cleanupGrammarFuzzer() {
    char socketPath[512];
    snprintf(socketPath, sizeof(socketPath), "/tmp/honggfuzz_socket.%i", getpid());
    unlink(socketPath);
}
