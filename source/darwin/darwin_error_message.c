#include "darwin_error_message.h"
#include <Security/SecCertificate.h>

void aws_darwin_log_message(
    enum aws_log_level log_level,
    aws_log_subject_t subject,
    char *function_name,
    OSStatus status) {

    CFStringRef msg_cfstring = SecCopyErrorMessageString(status, NULL);
    char msg_buf[512];
    bool msg_buf_valid = false;
    if (msg_cfstring) {
        msg_buf_valid = CFStringGetCString(msg_cfstring, msg_buf, sizeof(msg_buf), kCFStringEncodingUTF8);
    }
    if (!msg_buf_valid) {
        strncpy(msg_buf, "Unknown", sizeof(msg_buf));
    }
    AWS_LOGF(
        log_level,
        subject,
        "Darwin system function %s failed with error code %d (%s)\n",
        function_name,
        (int)status,
        msg_buf);
    if (msg_cfstring) {
        CFRelease(msg_cfstring);
    }
}
