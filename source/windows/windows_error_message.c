#include "windows_error_message.h"
#include <Windows.h>
#include <aws/common/allocator.h>
#include <aws/io/logging.h>

void aws_win_log_message(
    enum aws_log_level log_level,
    aws_log_subject_t subject,
    char *function_name,
    DWORD last_error) {
    WCHAR wstr[512]; // Buffer for text.
    DWORD dw_chars;
    char *buffer;
    int size_needed;
    struct aws_allocator *allocator = aws_default_allocator();

    dw_chars = FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, last_error, 0, (LPSTR)buffer, 512, NULL);
    if (dw_chars) {
        size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)dw_chars, NULL, 0, NULL, NULL);
        buffer = aws_mem_calloc(allocator, size_needed, sizeof(char));
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)dw_chars, &buffer[0], size_needed, NULL, NULL);
    } else {
        buffer = "Error message not found.";
    }
    AWS_LOGF(
        log_level,
        subject,
        "Windows system function %s failed with error code %d (%s)\n",
        function_name,
        last_error,
        buffer);
    if (dw_chars) {
        aws_mem_release(allocator, buffer);
    }
}
