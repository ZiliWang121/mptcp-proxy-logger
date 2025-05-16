// mpsched.h
#ifndef MPSCHED_H
#define MPSCHED_H

#define NUM_SUBFLOWS 8

struct MPTCPResult {
    unsigned int subflow[NUM_SUBFLOWS][9];
    int count;
};

int get_sub_info(int fd, struct MPTCPResult* out);
int persist_state(int fd);

#endif
