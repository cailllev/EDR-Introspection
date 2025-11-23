#include <core/context.h>
#include <core/pebwalker.h>
#include <epic.h>
#include <libc/stdbool.h>
#include <libc/stdint.h>
#include <libc/stdlib.h>
#include <modules/utils/utils.h>

void print_message() {
    auto ctx = GET_CONTEXT();
    utils::message(ctx->message, "Main");
}

extern "C" void main_pic() {
    auto ctx = GET_CONTEXT();

    wchar_t proc[] = L"explorer.exe";
    uint64_t pid = utils::get_pid_by_name(proc);
    if (pid == -1) {
        ctx->message = "Get pid failed!";
        print_message();
        return;
    }

    HANDLE h = utils::open_process_by_pid(pid);
    if (h == NULL) {
        ctx->message = "Unable to open proc!";
        print_message();
        return;
    }

    size_t bufferSize;
    char buffer[bufferSize];
    bool readOk = utils::read_data_section(h, &buffer, bufferSize);
    if (!readOk) {
        ctx->message = "Read data section failed!";
        print_message();
        return;
    }

    buffer[64] = 0; // null terminate
    ctx->message = buffer;
    print_message();
}