// https://developer.arm.com/documentation/ddi0360/f/control-coprocessor-cp15/summary-of-cp15-instructions  
  
  // ---------------------------------------------------------------------- Switch to Supervisor mode
  mrs r0, cpsr
  bic r0, r0, #0x1F     // clear mode bits
  orr r0, r0, #0x13     // set Supervisor mode
  msr spsr_cxsf, r0
  add r0, pc, #4        // hold (in ELR_hyp) the address to return to  (to make 'eret' working right)
  msr ELR_hyp, r0       // save the address in ELR_hyp
  eret                  // apply the mode change (Exception return)

  // ---------------------------------------------------------------------- Fill VBAR
  mrc p15, 0, r1, c12, c0, 0              // get VBAR
  mov r0, #0x8000                         // the address of our 8 handlers

  ldmia r0!, {r2,r3,r4,r5, r6,r7,r8,r9}   // load multiple registers from consecutive memory locations using an address from the register r0
  stmia r1!, {r2,r3,r4,r5, r6,r7,r8,r9}   // fill VBAR
  ldmia r0!, {r2,r3,r4,r5, r6,r7,r8,r9}   // continue filling VBAR...
  stmia r1!, {r2,r3,r4,r5, r6,r7,r8,r9}

  // ---------------------------------------------------------------------- Init cache
  mov r12,#0
  mcr p15, 0, r12, c7, c10, 1   // DCCMVAC - Clean data or unified cache line by virtual address to PoC.
  dsb                           // Data sync barrier
  mov r12, #0
  mcr p15, 0, r12, c7, c5, 0    // ICIALLU - Invalidate all instruction caches to PoU. If branch predictors are architecturally visible, also flush them.
  mov r12, #0
  mcr p15, 0, r12, c7, c5, 6    // BPIALL  - Invalidate all entries from branch predictors.
  dsb                           // Data sync barrier
  isb                           // Instruction sync barrier

  // ---------------------------------------------------------------------- Set secure state
  mrc p15, 0, r1, c1, c1, 0   // Get SCR  (Secure Configuration Register)
  bic r1, r1, #1              // Reset 'Non-secure' bit (set secure state)
  mcr p15, 0, r1, c1, c1, 0   // Write to SCR

  // ---------------------------------------------------------------------- Turn on Instruction cache
  mrc p15,0,r2,c1,c0,0 // Read Control Register
  orr r2, #0x1000    // Instruction cache
  //orr r2, #0x0800    // Branch prediction (does not affect this result)
  //orr r2, #0x0004    // Data cache        (does not affect this result)
  //orr r2, #0x0001  // MMU               (does not work! don't know why yet)
  mcr p15,0,r2,c1,c0,0