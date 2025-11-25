#include <core/context.h>
#include <core/pebwalker.h>
#include <epic.h>
#include <libc/stdbool.h>
#include <libc/stdint.h>
#include <libc/stdlib.h>
#include <modules/utils/utils.h>

extern "C" void main_pic() {
    wchar_t proc[] = L"explorer.exe";
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
    bool readOk = utils::proc_mini_dump(h, pid);
    utils::message("after dump", "main");
    if (!readOk) {
        utils::message("Write Minidump failed!", "main error");
        return;
    }
}