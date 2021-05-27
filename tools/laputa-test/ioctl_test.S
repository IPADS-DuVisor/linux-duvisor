#include "asm.h"

BEGIN_FUNC(infinite_loop)
    j .
END_FUNC(infinite_loop)


BEGIN_FUNC(loop_until_sip)
1:    
    csrr x1, sip
    and x1, x1 ,0x20
    beqz   x1, 1b
    ecall
END_FUNC(loop_until_sip)