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

## Running proof regression

The following will check all proofs assuming VCC and make are on your path.
For obtaining VCC, see the next section on building VCC in a Windows docker
container.

        $ make

## VCC docker container

I've tested the following on Windows 10 1809 with Docker Desktop 2.2.03.

1. Make sure that docker is running with Windows containers. Another good
sanity check is to ensure `docker run hello-world` works as expected.

2. Build the image (this takes about 30 minutes)

        docker build -t vcc docker-images/win10-vs2012/

3. Run an interactive powershell in a container

        docker run -it vcc powershell

4. Inside the container check VCC works

        vcc "C:\vcc\vcc\Test\testsuite\examples3\ArrayList.c"
        Verification of ArrayList#adm succeeded.[1.36]
        Verification of Length succeeded. [0.01]
        Verification of CreateArrayList succeeded. [0.05]
        Verification of MakeEmpty succeeded. [0.03]
        Verification of Select succeeded. [0.02]
        Verification of Update succeeded. [0.05]
        Verification of DisposeArrayList succeeded. [0.03]
        Verification of Add succeeded. [0.44]
        Verification of main_test succeeded. [0.67]
