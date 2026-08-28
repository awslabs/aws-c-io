/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IO_L4PROXY_IMPL_H
#define AWS_IO_L4PROXY_IMPL_H

#include <aws/io/io.h>

#include <aws/common/byte_buf.h>

enum aws_l4_proxy_protocol_status {
    AWS_L4PPS_IN_PROGRESS,
    AWS_L4PPS_SUCCESS,
    AWS_L4PPS_FAILURE,
};

/*
 * Input-output structure containing the results of an attempt to progress the auth negotiation
 */
struct aws_l4_proxy_negotiation_context {

    /* Incoming data to be processed.  Negotiation instance will update this based on bytes consumed */
    struct aws_byte_cursor *data;

    /* Resulting current status of the negotiation */
    enum aws_l4_proxy_protocol_status status;

    /* Data to write to the socket as part of the negotiation.  Caller must always initialize this. */
    struct aws_byte_buf *to_write;

    /* if the negotiation failed, this has the error code in it */
    int error_code;
};

#endif /* AWS_IO_L4PROXY_IMPL_H */
