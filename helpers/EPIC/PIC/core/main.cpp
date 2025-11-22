#include <core/context.h>
#include <core/pebwalker.h>
#include <epic.h>
#include <libc/stdbool.h>
#include <libc/stdint.h>
#include <libc/stdlib.h>
#include <modules/utils/utils.h>

void print_message() {
    auto ctx = GET_CONTEXT();
    utils::message(ctx->message);
}

extern "C" void main_pic() {
    auto ctx = GET_CONTEXT();
    ctx->message = "Start";
    print_message();

    int pid = 5716;
    uint64_t addr = 0x7FF728920000LL; // proc base

    char buffer[2];
    memset(buffer, 0, sizeof(buffer));
    HANDLE h = utils::open_process_by_pid(pid);
    if (h != NULL) {
        if (utils::read_memory(h, addr, buffer, sizeof(buffer))) {
            buffer[sizeof(buffer)] = 0; // null terminate
            ctx->message = buffer;
            utils::message(ctx->message);
        }
        else {
            ctx->message = "Read Memory failed";
            print_message();
        }
    }
    else {
        ctx->message = "Unable to open proc!";
        print_message();
    }

    ctx->message = "Done";
    print_message();
}