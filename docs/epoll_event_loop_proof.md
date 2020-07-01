# VCC Proof Signoff

Verification tool: VCC (code-level proof)

Proofs: tests/vcc/

Implementation: Linux event loop (`source/linux/epoll_event_loop.c`)

Specification / Properties (`preamble.h`):
  - *Memory safety*: the implementation only accesses valid memory.
  - *Thread safety*: threads only update objects that they own.
  - *Functional correctness*: sequential task and event callback execution in
    the presence of multiple client threads. The proofs verify that:
    - The scheduler for task execution is thread-local to the event loop
      thread (so is sequential since no other threads read or write directly to
      the scheduler). Tasks move from client threads to the event loop via
      properly-synchronized ownership transfers, using locking.
    - Subscribe/notify for event execution is properly-synchronized via epoll.

## Assumptions

Generally, we assume well-behaved clients; the correctness of underlying
primitives (memory allocation, AWS C Common library, syscalls); and, minor
assumptions due to limitations in VCC. More precisely, the proofs assume:

  - Well-behaved client: all client threads use the event loop API in a manner
    that adheres to the specification. A badly-behaved client can invalidate
    the proven properties. For example, a client that reads, writes, or frees a
    task struct object that is scheduled on the event loop is racy and no
    longer thread safe. The specification given in `preamble.h` forbids this
    behavior (the ownership of the task struct changes as a result of the
    schedule function) but we cannot, in general, enforce this behavior since
    we do not verify client code.

  - Thread safety of the allocator functions `aws_mem_{calloc,release}`. This is
    important in the case where a client uses a custom allocator.

  - Memory safety and function contracts for the following AWS C Common functions:

        aws_atomic_compare_exchange_ptr
        aws_atomic_{init, load, store}_{int, ptr}
        aws_linked_list_{init, pop_front, swap_contents}
        aws_mutex_{lock, unlock}
        aws_raise_error
        aws_task_init
        aws_task_scheduler_schedule_{now, future}
        aws_task_scheduler_{init, run_all, clean_up, cancel_tasks, has_tasks}
        aws_thread_{init, current_thread_id, launch, join, clean_up, thread_id_equal}

    and similarly for the AWS C-IO functions:

        aws_event_loop_{init_base, clean_up_base}
        aws_open_nonblocking_posix_pipe

    and similarly for the system calls:

        close
        epoll_{ctl, wait, create}
        eventfd
        read, write

    The contracts are given in the `preamble.h` and proof files. The contracts
    are assumed, not proven. The memory safety of the AWS C Common linked list
    functions have been proven in CBMC.

  - Thread safety of the epoll syscalls `epoll_{ctl, wait}`. We additionally
    assume that the `ctl` (subscribe) and `wait` syscalls induce "happens
    before" so that the litmus test (See Appendix) is data-race free and
    therefore properly-synchronizes event subscribe/notify.

  - Minor assumptions due to limitations of the VCC tool.

    - In `s_is_on_callers_thread` we assume the loaded value from the atomic
      var `running_thread_id` is thread-local and either `NULL` or the address
      of the owner of the event loop. We cannot make this an object invariant
      because the access is atomic. We manually validate that this assumption
      is reasonable.

    - In `s_run` we do not model the ownership transfer of the event loop from
      the client thread to the freshly-launched event loop thread. We manually
      validate that this assumption is reasonable.

  - The Sequentially Consistent Data Race Free (SC-DRF) guarantee required by
    the C11 standard: if a program is race-free and contains no non-SC atomic
    operations, then it has only SC semantics [Note 12, N1570]. We rely on
    SC-DRF to justify the use of VCC's SC memory model. We manually
    validate that the event loop implementation contains no non-SC atomic
    operations. Validation is required for pre-C11 compilers.

## Simplifications

  - Omit modeling of hash-table `local_data` in event loop.
  - The log functions `AWS_LOGF_{...}` are no-ops (hash-defined out).
  - Allocator functions are hash-defined to malloc/free.
  - In `s_destroy`, we (re-)take the `epoll_loop` pointer after stop and wait
    have been called. This has no semantic change to the program but is
    necessary for the proof.
  - Workarounds for VCC frontend (no semantic diff, but changes to syntax)

        // Function pointer declarations
        // For example, the following
        typedef int(aws_io_clock_fn)(uint64_t *timestamp);
        // is replaced with
        typedef int(* aws_io_clock_fn_ptr)(uint64_t *timestamp);

        // Array and struct literal initializers
        // For example, the following
        int pipe_fds[2] = {0};
        // is replaced with
        int pipe_fds[2]; pipe_fds[0] = 0; pipe_fds[1] = 0;

## Trusted computing base

  - Soundness of verification tools: VCC, Boogie, Z3
  - C Compiler, because the verification is at the C code-level and the
    properties proved may not be preserved by compilation.

## References

[N1570] ISO/IEC. Programming languages – C. International standard 9899:201x,
2011

## Appendix

Assumption on "happens before" induced by `epoll_{ctl/wait}`. Informally,
we need "message-passing" to hold so that the shared data passed from T1-to-T2
is guaranteed not-to-race.

        // Initially *data == 0 (non-atomic location)
        // T1
        *data = 1;
        epoll_ctl(...); // register event

        // T2
        if (1 == epoll_wait(...)) { // receive event
            r0 = *data; // guaranteed that r0==1
        }
