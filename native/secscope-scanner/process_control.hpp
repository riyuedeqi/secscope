#pragma once

#include "native_io.hpp"

namespace secscope {

// Execute one explicitly requested and audited process-control action. This
// entry point is intentionally separate from scan/resume and scheduled paths.
int run_process_control(const Arguments& args);

}
