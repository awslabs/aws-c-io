## AWS-C-IO

This is a module for the AWS SDK for C. It handles all IO and TLS work for application protocols. 

aws-c-io is an event driven framework for implementing application protocols. It is built on top of
cross-platform abstractions that allow you as a developer to think only about the state machine and API
for your protocols. A typical use-case would be to write something like Http on top of asynchronous-io
with TLS already baked in. All of the platform and security concerns are already handled for you.

It is designed to be light-weight, fast, portable, and flexible for multiple domain usecases such as:
embedded, server, client, and mobile.

## License

This library is licensed under the Apache 2.0 License. 

## Concepts

### Event Loop
Core to Async-IO is the event loop. We provide an implementation for most platforms out of the box:

Platform | Implementation
--- | ---
Linux | Edge-Triggered Epoll
BSD Variants and Apple Devices | KQueue
Windows | IOCP (IO Completion Ports)
Default Fallback | Select
Custom | Whatever you want!

An Event Loop has a few jobs.

1. Notify subscribers of IO Events
2. Execute and maintain a task scheduler
3. Maintain an opaque data store for consumers

The threading model for a channel (see below) is pegged to the thread for the event loop.

### Channels and Slots
A channel is simply a container that drives the slots. It is responsible for providing an interface
between slots and the underlying event-loop, as well as invoking the slots to pass messages. As a channel 
runs, it makes sure that all messages queues are empty before returning control to the caller. It also provides
utilities for making sure slots and their handlers run in the correct thread, and moving execution to that thread
if necessary.

![Channels and Slots Diagram](docs/images/channels_slots.png)

In this diagram, a channel is a collection of slots, and it knows how to make them communicate. It also controls the 
lifetime of slots.

### Slots
![Slots Diagram](docs/images/slots.png)

Slots contain 2 queues, one for the write direction, and one for the read direction. In addition they maintain their links
to adjacent slots in the channel. Most importantly, they contain a reference to a handler. Handlers are responsible for doing
most of the work (see below). Finally, slots have an API that manages invoking the handler, from the channel's perspective, as well
as utilities for manipulating the connections of the slots themselves.

### Channel Handlers
The channel handler is the fundamental unit that protocol developers will work with. It contains all of your
state machinery, framing, and optionally end-user APIs.

![Handler Diagram](docs/images/handler.png)

Channel Handlers are runtime polymorphic. Here's some detail on the virtual table (v-table).

`int data_in ( struct aws_io_message *msg)`

Data in is invoked by the slot when an application level message is received in the read direction (from the io).
The job of the implementer is to process the data in msg and either notify a user or queue a new message on the slot's
read queue.

`int data_out (struct aws_io_message *msg)`

Data Out is invoked by the slot when an application level message is received in the write direction (to the io).
The job of the implementer is to process the data in msg and either notify a user or queue a new message on the slot's
write queue.

`size_t update_window (size_t size_)`

Update Window is invoked by the slot when a framework level message is received from an downstream handler.
It only applies in the read direction. This gives the handler a chance to make a programatic decision about 
what it's read window should be. The return value will be passed to the next adjacent handler.

`int shutdown_notify (int error_code_)`

Shutdown notify is invoked by the slot when a framework level message is received from an upstream handler.
This notifies the handler that the previous handler in the chain has shutdown and will no longer be sending or
receiving messages.

`int shutdown_direction ( enum aws_channel_direction dir_)`

Shutdown direction is invoked by the slot to close the message processing in a given direction (either read, write, or both).
This is a notification to begin the process. For example, in TLS, there is a shutdown sequence that happens between client and server,
so it may take a few ticks of the event loop for this process to finish. A handler will invoke shutdown_notify when it has
completed this process.

`void destroy()`

Clean up any memory or resources owned by this handler, and then deallocate the handler itself.

#### Special, pre-defined handlers
Out of the box you get a few handlers pre-implemented.
1. Sockets. We've done the heavy lifting of implementing a consistent sockets interface for each platform.
Sockets interact directly with the underlying io and are invoked directly by the event loop for io events.
2. Pipes (or something like them depending on platform), these are particularly useful for testing.
3. TLS. We provide TLS implementations for most platforms.

Platform | Implementation
--- | ---
Linux | Signal-to-noise (s2n) see github.com/awslabs/s2n
BSD Variants | s2n
Apple Devices | Security Framework
Windows | SecureChannel
Custom | You can always write your own

### Typical Channel
![Typical Channel Diagram](docs/images/typical_channel.png)

A typical channel will contain a socket handler, which recieves io events from the event loop.
It will read up to 16 kb and pass the data to the next handler. The next handler is typically 
feeding a TLS implementation (see the above section on pre-defined handlers). The TLS handler
will then pass the data to an application protocol. The application protocol could then expose an
API to an application. When the application wants to send data, the whole process runs in reverse.

Channels can be much more complex though. For example, there could be nested channels for multiplexing/demultiplexing,
or there could be more handlers to cut down on handler complexity.

Note however, that a channel is always pegged to a single thread. It provides utilities for applications and
handlers to move a task into that thread, but it is very important that handlers, and application users
of your handlers never block.

### Read Back Pressure

TBD

![Read Back Pressure Diagram](docs/images/read_backpressure.png)
