#include <core/context.h>
#include <core/pebwalker.h>
#include <epic.h>
#include <libc/stdbool.h>
#include <libc/stdint.h>
#include <libc/stdlib.h>
#include <modules/hello/hello.h>
#include <modules/proc/proc.h>

void print_message() {
    auto ctx = GET_CONTEXT();
    hello::message(ctx->message);
}

extern "C" void main_pic() {
    auto ctx = GET_CONTEXT();
    ctx->message = "Hello EPIC!";
    print_message();

    char proc[] = {'e', 'x', 'p', 'l', 'o', 'r', 'e', 'r', '.', 'e', 'x', 'e', '\0'};

    if (EXISTS(open_process_by_name_pic)) {
        HANDLE h = open_process_by_name_pic(proc);
        if (h) {
            ctx->message = "!OPENED EXPLORER OMG!";
            print_message();

            if (EXISTS(close_handle_pic))
                close_handle_pic(h);
        }
        else {
            ctx->message = "Failed to open, sagde...";
            print_message();
        }
    }
    else {
        ctx->message = "No such function, NANI?!";
        print_message();
    }

    ctx->message = "Bye EPIC!";
    print_message();
}