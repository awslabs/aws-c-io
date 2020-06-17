# VCC Proofs of the Linux epoll event loop

This directory gives the specification and annotated source-code implementation
of the Linux epoll event loop implementation of C-IO. See
`docs/epoll_event_loop_proof.md` for an overview of the properties proven,
assumptions and simplifications.

## Reading the proofs

The majority of the specification is given in the header file `preamble.h`,
which specifies a contract (preconditions and postconditions) for each
implementation function.

The proofs themselves are the source code of the Linux epoll event loop
implementation with VCC annotations embedded alongside to guide VCC.
We split the event loop functions over the following files:

  - `cancel_task.c`
  - `is_on_callers_thread.c`
  - `lifecycle.c`
  - `main_loop.c`
  - `new_destroy.c`
  - `process_task_pre_queue.c`
  - `schedule.c`
  - `subscribe.c`
  - `unsubscribe.c`

Additionally, the file `client.c` shows some simple uses of the event loop API,
demonstrating that the specifications can be used together in a meaningful way.
