/*
* Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/

#include <aws/io/host_resolver.h>

void aws_host_resolver_destroy(struct aws_host_resolver *resolver) {
    assert(resolver->vtable.destroy);
    resolver->vtable.destroy(resolver);
}

int aws_host_resolver_resolve_host(struct aws_host_resolver *resolver, const struct aws_string *host_name,
                                   uint64_t max_ttl, on_host_resolved_result res, void *user_data) {
    assert(resolver->vtable.resolve_host);
    return resolver->vtable.resolve_host(resolver, host_name, max_ttl, res, user_data);
}

AWS_IO_API int aws_host_resolver_purge_cache(struct aws_host_resolver *resolver) {
    assert(resolver->vtable.purge_cache);
    return resolver->vtable.purge_cache(resolver);
}
