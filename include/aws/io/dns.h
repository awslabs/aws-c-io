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

#include <aws/common/atomics.h>

struct aws_array_list;
struct aws_event_loop_group;
struct aws_string;

/* use async destruction from the start */
typedef void(aws_dns_on_destroy_completed_fn)(void *user_data);

/*
 * Vocabulary/Concepts
 *
 * aws_dns_resolver - A thin interface around remote DNS queries.  Includes a default implementation that supports
 * recursive and iterative queries.  Supports DNS over UDP.  (Eventually) Supports DNS over https and tls.  No support
 * for non-internet-class queries.  Uses a vtable and can be replaced with a custom implementation.
 *
 * aws_dns_service_provider_config - Controls what host/port/protocol combos the default aws_dns_resolver uses to
 * resolve queries.
 *
 * aws_host_resolution_service - A heavy-weight host name resolution service that contains CRT-specific and
 * getadrrinfo() specific functionality in the name of resolving DNS queries for CRT connections.  Contains
 * a TTL-based resolution cache and uses an aws_dns_resolver to resolve queries that the local cache cannot handle.
 * Uses a vtable and can be replaced with a custom implementation.
 * This will be the type directly used by channel setup.
 */

/*
 * Part 1 - aws_dns_service_provider_config
 * An abstraction around configuring/selecting a remote dns service provider.  Used by the default aws_dns_resolver to
 * choose an appropriate remote provider to resolve a query.
 *
 * Desired Use Cases
 *
 * (1) EzMode - You don't want to deal with a lot of configuration nonsense that you don't understand.  With minimal
 * effort or understanding, you want to have a resolver that matches standard system behavior (getaddrinfo()-based).
 *
 * (2) Testing - You're writing tests.  You want a resolver that can use custom (usually localhost-based) endpoints
 * for complete integration testing.
 *
 * (3) Privacy - You're concerned about privacy. You want a DNS resolver that does not broadcast every lookup you do.
 *
 * (4) Cache bypass (s3) - You want certain queries to bypass resolution caching as much as possible.  The only way
 * to do this is to perform iterative queries starting at the root (or nearest ancestor) to discover the authoritative
 * name server and then hit it directly with a query.
 *
 * The aws dns resolver implementation uses this abstraction, as well as a query's properties, to determine
 * which remote dns provider to use to resolve a query that is not cache-satisfiable.
 *
 * The configuration object allows you to override providers for three different categories:
 *
 *  (1) bootstrap - This provider will be used to resolve all other unresolved providers (default and root).
 *  There can only be one bootstrap provider and its host entry MUST be a resolved ipv4 or ipv6 address.
 *
 *  (2) default - This provider will be used to resolve all normal dns queries.  There can only be one default
 *  provider.
 *
 *  (3) root - this provider (or these providers) will be used to resolve cache-bypassing
 *  iterative queries.  As the name suggests, this should literally be a list of root nameserver host names.
 *  There can be (and should be, for redundancy and reliability) more than one root provider, and an aws_dns_resolver
 *  will iterate through the full set in round robin fashion as needed.
 *
 * Why are roots necessary?  The purpose of the cache-bypass use case is to seed the local resolver cache with
 * many different results (so as to distribute connections as uniformly as possible across VIPs).  It only provides
 * value for host names that map to large sets of addresses.  It isn't sufficient to simply NOT set recursion-desired on
 * a standard query (which, by specification, will return next-step nameservers if authoritative data is not available)
 * because we don't care about the distinction between authoritative vs. cached data.  We're after distinct addresses
 * and we don't get that unless we hit the authoritative name server ourselves.
 *
 * For each category, if not overridden, an aws_dns_resolver will:
 *
 *   (1) bootstrap - Default to standard system behavior (ala getaddrinfo()).
 *   (2) default - Use the bootstrap provider.
 *   (3) root - Use the default provider (to resolve iterative queries).
 *
 * Returning to our original use cases:
 *
 *  (1) EzMode - Use an empty, unmodified provider config and get standard system default behavior (as if
 *  getaddrinfo() was used) in all cases.
 *
 *  (2) Testing - Set bootstrap and default to a loopback address that has a mock listener attached to it.  Roots
 *  can be set too to test iterative resolves.
 *
 *  (3) Privacy - Leave the bootstrap alone (use standard behavior to set up your default provider) but set the
 *  default to something you trust (for example, a remote host that supports dns-over-https or dns-over-tls)
 *
 *  (4) Cache bypass - Add one or more root name servers to the root category.  They will be used as the start points
 *  for resolving iterative queries (when the label cache does not have better starting information).
 *
 * Not yet solved (unsure if necessary):
 *
 *  (1) Do we need additional information on the provider record to support the
 *  (unlikely) case of getting a truncated result and being unable to get around it via edns(0) options?  In
 *  particular, would a fallback port for a tcp connection be useful and sufficient?
 *
 *  (2) Do we need to publicly expose the logic that emulates getaddrinfo()-equivalent provider selection?  Possibly
 *  asynchronous.
 *
 *  (3) Multiple default providers?  In particular, we don't yet know enough about how getaddrinfo() selects a host.
 *  If it's dynamic we will need to refactor.
 */

enum aws_dns_protocol {
    AWS_DNS_PROTOCOL_UDP,
    AWS_DNS_PROTOCOL_TCP,
    AWS_DNS_PROTOCOL_TLS,
    AWS_DNS_PROTOCOL_HTTPS,
};

struct aws_dns_service_provider_record {
    enum aws_dns_protocol protocol;
    struct aws_byte_cursor host;
    uint16_t port;
};

struct aws_dns_service_provider_config {

    /* If not set, the resolver will use getaddrinfo()-equivalent logic to select the bootstrap provider */
    struct aws_dns_service_provider_record *bootstrap_provider;

    /* If not set, the resolver will use the bootstrap provider for all recursive queries */
    struct aws_dns_service_provider_record *default_provider;

    /* If empty, the resolver will use the default provider for iterative queries */
    struct aws_dns_service_provider_record *root_providers; /* beginning of an array */
    uint32_t root_provider_count;
};

/*
 * Part 2 - aws_dns_resolver
 * A thin interface around raw dns query/response.  A default resolver is included that uses
 * aws_dns_service_provider_config to control what remote dns services are used.
 *
 * Musts/Requirements:
 *   (1) 1 question allowed per query (aggregation is caller's responsibility)
 *   (2) Implements retries (users should not layer retry on top)
 *
 * Shoulds:
 *   (1) Cache authority/zones-of-responsibility in a label-based tree (iterative only?)
 *   (2) Assume query input is a host name and not an IP address.
 *
 * Must nots:
 *   (1) No caching of answers
 *   (2) No getaddrinfo-specific post-processing or pre-processing
 *   (3) No CRT-specific functionality (ipv6 vs. ipv4, result caching, etc...)
 *
 * Open Possibilies:
 *   (1) Reverse lookup support
 *   (2) Security (DNSSEC, DNSCURVE, etc...) support
 */

/*
 * Exactly matches specification RR type used in query/answer.
 * Includes obsolete/unused record types for completeness.
 *
 * Initially we care (internally) about A, AAAA, NS, SOA, and CNAME
 * Initially we care (externally) about A, AAAA
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
    AWS_DNS_RR_ISDN = 20,
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
    AWS_DNS_RR_SRV = 33,    /* AWS_DNS_RR_NBSTAT errorneously defined as 33 */
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

struct aws_dns_resource_record {
    /* Needs to be on the record (rather than the full result/set) to support ANY-based queries */
    enum aws_dns_resource_record_type type;

    /* time-to-live in seconds */
    uint32_t ttl;

    /* raw binary data of the resource record */
    struct aws_string *data;
};

/* what kind of query to make */
enum aws_dns_query_type {
    /*
     * Make a recursive query to a single provider
     */
    AWS_DNS_QUERY_RECURSIVE,

    /*
     * Performs an iterative query starting from the closest known (name server) ancestor to the host
     * in question.
     */
    AWS_DNS_QUERY_ITERATIVE,
};

/* various configuration options for an individual query */
struct aws_dns_query_options {
    enum aws_dns_query_type query_type;

    /*
     * Retry controls
     *
     * Open Q: Move to a generic retry strategy type?
     */

    /*
     * (Iterative only) Maximum (packet-level) queries (summed across attempts?) to send before giving up.
     * If zero, defaults to something reasonable (20?)
     */
    uint16_t max_iterations;

    /*
     * Maximum number of attempts to try the query (against no response).
     * If zero, defaults to 4.
     */
    uint16_t max_retries;

    /*
     * Time to wait for a response before considering the attempt a failure and potentially retrying.
     * If zero, defaults to 4000.
     */
    uint16_t retry_interval_in_millis;
};

/*
 * There are extensions/proposals for extended error information.  Unspecified for now.
 */
struct aws_dns_query_result_extended_info;

struct aws_dns_query_result {
    /* array of aws_dns_resource_record */
    struct aws_array_list records;

    struct aws_dns_query_result_extended_info *extended_info;
    bool authoritative;
    bool authenticated;

    /*
     * Truncation can also be an error, but if we get enough data for a valid answer and aren't doing security
     * validation, then it may be safe to return the answer without an error.  In that case, we'd indicate the
     * truncation status here.
     */
    bool truncated;
};

typedef void(on_dns_query_completed_callback_fn)(struct aws_dns_query_result *result, int error_code, void *user_data);

struct aws_dns_query {
    enum aws_dns_resource_record_type query_type;
    struct aws_byte_cursor hostname;

    struct aws_dns_query_options *options; /* Optional - If null, all defaults will be used */

    on_dns_query_completed_callback_fn *on_completed_callback;
    void *user_data;
};

struct aws_dns_resolver;

struct aws_dns_resolver_vtable {
    void (*destroy)(struct aws_dns_resolver *resolver, aws_dns_on_destroy_completed_fn *callback, void *user_data);
    void (*make_query)(struct aws_dns_resolver *resolver, struct aws_dns_query *query);
};

struct aws_dns_resolver {
    struct aws_allocator *allocator;
    struct aws_dns_resolver_vtable *vtable;
    struct aws_atomic_var ref_count;
    void *impl;
};

/*
 * Configuration options for the crt's default dns resolver
 */
struct aws_dns_resolver_default_options {
    struct aws_dns_service_provider_config *providers;
    struct aws_event_loop_group *elg;

    aws_dns_on_destroy_completed_fn *destroy_completed_callback;
    void *destroy_user_data;
};

AWS_EXTERN_C_BEGIN

AWS_IO_API
struct aws_dns_resolver *aws_dns_resolver_new_default(
    struct aws_allocator *allocator,
    struct aws_dns_resolver_default_options *options);

AWS_IO_API void aws_dns_resolver_acquire(struct aws_dns_resolver *resolver);

AWS_IO_API void aws_dns_resolver_release(struct aws_dns_resolver *resolver);

AWS_IO_API
int aws_dns_resolver_make_query(struct aws_dns_resolver *resolver, struct aws_dns_query *query);

AWS_EXTERN_C_END

/******************************************************************************************************************
 * Part 3 - aws_host_resolution_service
 * A host-resolution service that uses an aws_dns_resolver in the service of CRT-specific host resolution functionality.
 *
 * Intended Properties:
 *   (1) Aggregation of ipv4 and ipv6 results in a single set
 *   (2) getaddrinfo() style sorting of results
 *   (3) Result caching
 *   (4) Host ranking/scoring based on connectivity/performance (API TBD)
 *   (5) Support various cache seeding strategies (for example, S3 front end addresses)
 *
 * Excluded Properties:
 *   (1) AWS service-specific policies.  Instead we support options that let an external user implement these policies.
 *
 * It's useful to acknowledge that, from the CRT's perspective, there are at least two kinds of queries we want to
 * support at the host resolution level:
 *   (1) channel setup queries - a standard name resolution process that yields ipv4 and ipv6 addresses for a connection
 *   (2) cache seeding queries - a resolution configuration that is intended to seed the internal cache with answers
 *   (ideally) ahead-of-time.  Options should exist to control how many distinct answers to try and establish.
 *
 * The current host resolution design does not support recurrent controls on cache seeding, making the assumption that
 * an external system should be responsible for over-time maintenance by making cache seeding queries periodically.
 * This is subject to change, given the privileged view the resolution service has of the cache and when it would
 * be proper to make additional queries.
 ******************************************************************************************************************/

/*
 * A host resolution query contains three sets of options (on top of what to actually look up):
 *
 * (1) How to read from the cache.
 * (2) How to perform the network-level query if the cache couldn't provide an answer.
 * (3) How to write back to the cache if a network-level query successfully returned results.
 */

enum aws_host_resolution_service_cache_read_mode {
    /*
     * If the cache has a valid answer, use it.  If there's a pending query for the same address, wait on it.
     */
    AWS_HRS_CRM_NORMAL,

    /*
     * Don't use the cache at all.  Skip directly to the resolver query.
     */
    AWS_HRS_CRM_SKIP,

    /*
     * Name and detailed semantics a WIP.
     * This is an option intended for cache seeding.
     * If there's fewer than N (cached results + pending queries), make a new pending query, otherwise select one
     * at random? (ideally uniform and round robin, not random)  Intent is a policy that loosely specifies a desired
     * target number of distinct addresses.  So if I'm about to do a 10-part multi-upload, I could pre-seed the cache
     * (if possible) by making 10 queries in SPREAD_N mode with N set to 10.
     *
     * Note that pre-seeding has some conflicts with S3's very-short TTL policy.  Based on performance results, if
     * SPREAD_N proves useful, we may also want to include a cache write mode that lets use override the TTL to a more
     * reasonable value than 6 seconds, while still being safe relative to ec2 ip shuffles (although TLS with SNI
     * should prevent mistaken connections to no-longer-valid hosts).
     */
    AWS_HRS_CRM_SPREAD_N,
};

struct aws_host_resolution_service_cache_read_options {
    enum aws_host_resolution_service_cache_read_mode mode;
    uint32_t spread_mode_count;
};

enum aws_host_resolution_service_cache_write_mode {
    /*
     * Write the answer(s) back to the cache as normal using the associated TTLs
     */
    AWS_HRS_CWM_NORMAL,

    /*
     * Don't write to the cache at all.
     */
    AWS_HRS_CWM_SKIP,
};

struct aws_host_resolution_service_cache_write_options {
    enum aws_host_resolution_service_cache_write_mode mode;
};

struct aws_host_resolution_service_resolve_options {
    enum aws_dns_query_type query_type;
};

/*
 * Success implies at least one non-null address.
 */
struct aws_dns_host_address_pair {
    struct aws_string *ipv4_address;
    struct aws_string *ipv6_address;
};

typedef void(on_host_resolution_query_completed_fn)(
    struct aws_dns_host_address_pair *addresses,
    int error_code,
    void *user_data);

struct aws_host_resolution_query {

    /*
     * If null, defaults to NORMAL read mode
     */
    struct aws_host_resolution_service_cache_read_options *cache_read_options;

    /*
     * If null, defaults to NORMAL write mode
     */
    struct aws_host_resolution_service_cache_write_options *cache_write_options;

    /*
     * If null, defaults to RECURSIVE query type
     */
    struct aws_host_resolution_service_resolve_options *resolve_options;

    struct aws_byte_cursor host_name;

    on_host_resolution_query_completed_fn *on_query_completed;
    void *user_data;
};

struct aws_host_resolution_service;

struct aws_host_resolution_service_vtable {
    void (*destroy)(struct aws_dns_resolver *resolver, aws_dns_on_destroy_completed_fn *callback, void *user_data);
    int (*resolve)(struct aws_host_resolution_service *service, struct aws_host_resolution_query *query);
};

struct aws_host_resolution_service {
    struct aws_allocator *allocator;
    struct aws_host_resolution_service_vtable *vtable;
    struct aws_atomic_var ref_count;
    void *impl;
};

/*
 * Configuration options for the default host resolution service
 *
 * ToDo: There's a lot of cache configuration that could be done here.
 */
struct aws_host_resolution_service_default_options {
    struct aws_dns_resolver *resolver;

    aws_dns_on_destroy_completed_fn *destroy_completed_callback;
    void *destroy_user_data;
};

AWS_EXTERN_C_BEGIN

/**
 * Creates a new default host resolution service with a ref count of 1.  The default host resolution service
 * implements all of the CRT's name resolution requirements.
 */
AWS_IO_API struct aws_host_resolution_service *aws_host_resolution_service_new_default(
    struct aws_allocator *allocator,
    struct aws_host_resolution_service_default_options *options);

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
AWS_IO_API int aws_host_resolution_service_resolve(
    struct aws_host_resolution_service *service,
    struct aws_host_resolution_query *query);

AWS_EXTERN_C_END

/*
 * Part 4 - Misc helper functionality
 */
enum aws_ip_address_type {
    AWS_IP_AT_NONE,
    AWS_IP_AT_IPV4,
    AWS_IP_AT_IPV6,
};

AWS_EXTERN_C_BEGIN

AWS_IO_API enum aws_ip_address_type aws_host_name_classify(struct aws_byte_cursor *host_name);

AWS_EXTERN_C_END

#endif /* AWS_IO_DNS_H */
