#ifndef AWS_IO_DNS_H
#define AWS_IO_DNS_H
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

#include <aws/io/io.h>

struct aws_array_list;
struct aws_event_loop_group;
struct aws_string;

/*
 * Part 1 - an abstraction around selecting a remote dns service to use.
 *
 * Two defaults are included:
 *   (1) An upstream provider that returns the platform-specific dns service that
 *     getaddrinfo() would use.  Note that the Windows implementation is a best-guess since
 *     the actual source is not available for study.
 *   (2) A chain provider that uses a fixed list of service provider hosts in a round-robin fashion.
 *
 *  Initially, all providers must be actual resolved addresses.  However, proper root-level
 *  support means we must allow root service providers to returns names (and resolve them with the
 *  upstream provider).  For obvious (chicken and egg) reasons, an upstream provider MUST
 *  always return a resolved address.
 *
 */

/*
 * Service provider selection feedback mechanism.  Non-success categories are a WIP.
 */
enum aws_dns_service_provider_result_type {
    AWS_DNS_SPRT_SUCCESS,
    AWS_DNS_SPRT_NO_ANSWER,
    AWS_DNS_SPRT_REJECTED,
};

struct aws_dns_service_provider;

AWS_EXTERN_C_BEGIN

AWS_IO_API
struct aws_dns_service_provider *aws_dns_service_provider_new_upstream(struct aws_allocator *allocator);

AWS_IO_API
struct aws_dns_service_provider *aws_dns_service_provider_new_chain(struct aws_allocator *allocator, char **host_list, uint32_t num_hosts);

AWS_IO_API void aws_dns_service_provider_acquire(struct aws_dns_service_provider *provider);

AWS_IO_API void aws_dns_service_provider_release(struct aws_dns_service_provider *provider);

AWS_IO_API
int aws_dns_service_provider_get_provider(struct aws_dns_service_provider *provider, struct aws_byte_cursor *provider_host);

AWS_IO_API
int aws_dns_service_provider_report_result(struct aws_dns_service_provider *provider, struct aws_byte_cursor *provider_host, enum aws_dns_service_provider_result_type result);

AWS_EXTERN_C_END

/*
 * Part 2 - a thin wrapper around raw dns query/response.
 *
 * Intended Properties:
 *   (1) 1 question allowed per query
 *   (2) Resolver caches authority/zones-of-responsibility in a label-based tree
 *   (3) Resolver supports injectable service providers (both upstream and root servers)
 *   (4) Resolver implements retries (users should not layer retry on top)
 *   (5) Resolver encapsulates transport (UDP only for now)
 *   (6) Resolver abstracts security (unsupported for foreseeable future)
 *
 * Excluded Properties:
 *   (1) No caching of answers
 *   (2) No getaddrinfo-specific functionality (result sorting, service provider selection)
 *   (3) No CRT-specific functionality (ipv6 vs. ipv4, result caching, etc...)
 *   (4) Input pre-processing (address vs. host name)
 *
 * Open Possibilies:
 *   (1) Revere lookups
 */

/*
 * Exactly matches specification RR type used in query/answer.
 * Includes obsolete/unused record types for completeness.
 */
enum aws_dns_resource_record_type {
    AWS_DNS_RR_A = 1,
    AWS_DNS_RR_NS = 2,
    AWS_DNS_RR_MD = 3,
    AWS_DNS_RR_MF = 4,
    AWS_DNS_RR_CNAME = 5,
    AWS_DNS_RR_SOA = 6,
    AWS_DNS_RR_MB = 7,
    AWS_DNS_RR_MG = 8,
    AWS_DNS_RR_MR = 9,
    AWS_DNS_RR_NULL = 10,
    AWS_DNS_RR_WKS = 11,
    AWS_DNS_RR_PTR = 12,
    AWS_DNS_RR_HINFO = 13,
    AWS_DNS_RR_MINFO = 14,
    AWS_DNS_RR_MX = 15,
    AWS_DNS_RR_TXT = 16,
    AWS_DNS_RR_RP = 17,
    AWS_DNS_RR_AFSDB = 18,
    AWS_DNS_RR_X25 = 19,
    AWS_DNS_RR_ISDM = 20,
    AWS_DNS_RR_RT = 21,
    AWS_DNS_RR_NSAP = 22,
    AWS_DNS_RR_NSAPPTR = 23,
    AWS_DNS_RR_SIG = 24,
    AWS_DNS_RR_KEY = 25,
    AWS_DNS_RR_PX = 26,
    AWS_DNS_RR_GPOS = 27,
    AWS_DNS_RR_AAAA = 28,
    AWS_DNS_RR_LOC = 29,
    AWS_DNS_RR_NXT = 30,
    AWS_DNS_RR_EID = 31,
    AWS_DNS_RR_NIMLOC = 32, /* AWS_DNS_RR_NB erroneously defined as 32 */
    AWS_DNS_RR_SRV = 33, /* AWS_DNS_RR_NBSTAT errorneously defined as 33 */
    AWS_DNS_RR_ATMA = 34,
    AWS_DNS_RR_NAPTR = 35,
    AWS_DNS_RR_KX = 36,
    AWS_DNS_RR_CERT = 37,
    AWS_DNS_RR_A6 = 38,
    AWS_DNS_RR_DNAME = 39,
    AWS_DNS_RR_SINK = 40,
    AWS_DNS_RR_OPT = 41,
    AWS_DNS_RR_APL = 42,
    AWS_DNS_RR_DS = 43,
    AWS_DNS_RR_SSHFP = 44,
    AWS_DNS_RR_IPSECKEY = 45,
    AWS_DNS_RR_RRSIG = 46,
    AWS_DNS_RR_NSEC = 47,
    AWS_DNS_RR_DNSKEY = 48,
    AWS_DNS_RR_DHCID = 49,
    AWS_DNS_RR_NSEC3 = 50,
    AWS_DNS_RR_NSEC3PARAM = 51,
    AWS_DNS_RR_TLSA = 52,
    AWS_DNS_RR_SMIMEA = 53,
    AWS_DNS_RR_HIP = 55,
    AWS_DNS_RR_NINFO = 56,
    AWS_DNS_RR_RKEY = 57,
    AWS_DNS_RR_TALINK = 58,
    AWS_DNS_RR_CDS = 59,
    AWS_DNS_RR_CDNSKEY = 60,
    AWS_DNS_RR_OPENPGPKEY = 61,
    AWS_DNS_RR_CSYNC = 62,
    AWS_DNS_RR_ZONEMD = 63,
    AWS_DNS_RR_SPF = 99,
    AWS_DNS_RR_UINFO = 100,
    AWS_DNS_RR_UID = 101,
    AWS_DNS_RR_GID = 102,
    AWS_DNS_RR_UNSPEC = 103,
    AWS_DNS_RR_NID = 104,
    AWS_DNS_RR_L32 = 105,
    AWS_DNS_RR_L64 = 106,
    AWS_DNS_RR_LP = 107,
    AWS_DNS_RR_EUI48 = 108,
    AWS_DNS_RR_EUI64 = 109,
    AWS_DNS_RR_TKEY = 249,
    AWS_DNS_RR_TSIG = 250,
    AWS_DNS_RR_IXFR = 251,
    AWS_DNS_RR_AXFR = 252,
    AWS_DNS_RR_MAILA = 253,
    AWS_DNS_RR_MAILB = 254,
    AWS_DNS_RR_ANY = 255,
    AWS_DNS_RR_URI = 256,
    AWS_DNS_RR_CAA = 257,
    AWS_DNS_RR_DOA = 259,
    AWS_DNS_RR_AMTRELAY = 260,
    AWS_DNS_RR_TA = 32768,
    AWS_DNS_RR_DLV = 32769,

};

enum aws_dns_query_algorithm {
    /*
     * Asks the local (hosts) upstream dns server to perform a recursive query.
     * Roughly equivalent to what getaddrinfo() makes (per resource record type).
     */
    AWS_DQRM_UPSTREAM,

    /*
     * Performs an iterative query starting from a dns root.  Root choice is configured
     * via a service provider.
     */
    AWS_DQRM_FROM_ROOT,

    /*
     * Performs an iterative query starting from the closest known ancestor to the host
     * in question.
     */
    AWS_DQRM_FROM_NEAREST_ANCESTOR,
};

struct aws_dns_query_options {
    enum aws_dns_query_algorithm algorithm;

    uint16_t max_iterations;
    uint16_t max_retries;
    uint16_t retry_interval_in_millis;

    bool authoritative_only;
};

/*
 * A thin abstraction/aggregation on top of the result code that can come in a single response.
 *
 * Purposely thin/WIP since it's not clear yet what the proper amount of aggregation/encapsulation should
 * be here.
 */
enum aws_dns_query_result_code {
    AWS_DNS_QUERY_RC_SUCCESS,
    AWS_DNS_QUERY_RC_NXDOMAIN,
    AWS_DNS_QUERY_RC_UNKNOWN,
};

struct aws_dns_resource_record {
    struct aws_string *data;

    /* Needs to be on the record (rather than the result/set) to support ANY-based queries */
    enum aws_dns_resource_record_type type;
};

/*
 * There are extensions/proposals for extended error information.  A pointer-referenced intermediate struct
 * supports that.
 */
struct aws_dns_query_result_extended_info;

struct aws_dns_query_result {
    enum aws_dns_query_result_code rc;
    struct aws_array_list records; /* array of aws_dns_resource_record */
    struct aws_dns_query_result_extended_info *extended_info;
    bool truncated;
    bool authoritative;
};

typedef void (*on_dns_query_completed_callback_fn)(struct aws_dns_query_result *result, int error_code, void *user_data);

struct aws_dns_query {
    enum aws_dns_resource_record_type query_type;
    struct aws_byte_cursor hostname;

    on_dns_query_completed_callback_fn on_completed_callback;
    void *user_data;
};


struct aws_dns_resolver_config_options {
    struct aws_dns_provider *upstream_provider;
    struct aws_dns_provider *root_provider;
    struct aws_event_loop_group *elg;
};

AWS_EXTERN_C_BEGIN

struct aws_dns_resolver;

AWS_IO_API
struct aws_dns_resolver *aws_dns_resolver_new(struct aws_allocator *allocator, struct aws_dns_resolver_config_options *options);

AWS_IO_API void aws_dns_resolver_acquire(struct aws_dns_resolver *resolver);

AWS_IO_API void aws_dns_resolver_release(struct aws_dns_resolver *resolver);

AWS_IO_API
int aws_dns_resolver_query(struct aws_dns_resolver *resolver, struct aws_dns_query *query, struct aws_dns_query_options *options);

AWS_EXTERN_C_END

/******************************************************************************************************************
 * Part 3 - A host-resolution service that uses an aws_dns_resolver in the service of CRT-specific functionality.
 *
 * Intended Properties:
 *   (1) Aggregation of ipv4 and ipv6 results in a single set
 *   (2) getaddrinfo() style sorting of results
 *   (3) Result caching that supports both replacement and appending
 *   (4) Host ranking/scoring based on connectivity/performance
 *
 * Excluded Properties:
 *   (1) AWS service-specific policies (S3 refresh, S3 front-end spread for multipart operations as examples).  The
 *     configuration options for queries are built to support these policies however.
 ******************************************************************************************************************/
enum aws_host_resolution_service_cache_read_mode {
    AWS_HRS_CRM_NORMAL,
    AWS_HRS_CRM_SKIP,
    AWS_HRS_CRM_SPREAD_N,
};

struct aws_host_resolution_service_cache_read_options {
    enum aws_host_resolution_service_cache_read_mode mode;
    uint32_t spread_mode_count;
};

enum aws_host_resolution_service_cache_write_mode {
    AWS_HRS_CWM_NORMAL,
    AWS_HRS_CWM_SKIP,
};

struct aws_host_resolution_service_cache_write_options {
    enum aws_host_resolution_service_cache_write_mode mode;
};

struct aws_host_resolution_service_resolve_options {
    enum aws_dns_query_algorithm algorithm;
};

typedef void (*on_host_resolution_query_completed_fn)(struct aws_array_list *addresses, int error_code, void *user_data);

struct aws_host_resolution_query {

    struct aws_host_resolution_service_cache_read_options *cache_read_options;
    struct aws_host_resolution_service_cache_write_options *cache_write_options;
    struct aws_host_resolution_service_resolve_options *resolve_options;

    struct aws_byte_cursor host_name;

    on_host_resolution_query_completed_fn *on_query_completed;
    void *user_data;
};

struct aws_host_resolution_service_options {
    struct aws_event_loop_group *elg;
    struct aws_dns_resolver *resolver;
};

struct aws_host_resolution_service;

AWS_EXTERN_C_BEGIN

/**
 * Creates a new host resolution service with a ref count of 1
 */
AWS_IO_API struct aws_host_resolution_service *aws_host_resolution_service_new(struct aws_allocator *allocator, struct aws_host_resolution_service_options *options);

/**
 * Adds 1 to the ref count of a host resolution service
 */
AWS_IO_API void aws_host_resolution_service_acquire(struct aws_host_resolution_service *service);

/**
 * Decrements 1 from the ref count of a host resolution service.  If the ref count drops to zero, the service will be
 * destroyed.
 */
AWS_IO_API void aws_host_resolution_service_release(struct aws_host_resolution_service *service);

/**
 * Submits a resolution query to the host resolution service.
 */
AWS_IO_API int aws_host_resolution_service_resolve(struct aws_host_resolution_service *service, struct aws_host_resolution_query *query);

AWS_EXTERN_C_END

/*
 * Part 4 - Misc helper functionality
 */
enum aws_ip_address_type {
    AWS_IP_AT_NONE,
    AWS_IP_AT_IPV4,
    AWS_IP_AT_IPV6
};

AWS_EXTERN_C_BEGIN

AWS_IO_API enum aws_ip_address_type aws_host_name_classify(struct aws_byte_cursor *host_name);

AWS_EXTERN_C_END

#endif /* AWS_IO_DNS_H */
