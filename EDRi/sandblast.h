#pragma once

enum RETURN_CODE {
	SUCCESS_NO_WAIT = 0,
	SUCCESS_WAIT = 1,
	FAILED = 2,
	TIMEOUT = 3
};
RETURN_CODE disable_wait_enable_kernel_callbacks();