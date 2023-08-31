//+build ignore

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#include "vmlinux/x86/vmlinux.h"

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
    u32 pid;
    u32 ppid;
    u32 exit_code;
    u64 duration_ns;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    bool exit_event;
} __attribute__((packed));

#endif /* __BOOTSTRAP_H */
