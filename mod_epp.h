
#ifndef EPP_H
#define EPP_H

#include "apr.h"
#include "apr_md5.h"
#include "apr_hash.h"
#include "httpd.h"
#include "util_filter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_INVALID_CMD 10
#define EPP_TCP_HEADER_SIZE 4		/* just one longword */
#define EPP_CHUNK_SIZE 2048		/* try to read that many bytes at once */
#define EPP_MAX_FRAME_SIZE 65536	/* don't accept larger xml data blocks */

module AP_MODULE_DECLARE_DATA epp_module;

#define EPP_DEFAULT_XML_ERROR "/epp/error/xmlparsing"
#define EPP_DEFAULT_XML_ERROR_SCHEMA "/epp/error/schema"
#define EPP_DEFAULT_COMMAND_ROOT "/epp/command"

#define EPP_CONTENT_TYPE_CGI "multipart/form-data; boundary=--BOUNDARY--"
#define EPP_CONTENT_PREFIX_CGI "----BOUNDARY--\r\nContent-Disposition: form-data; name=\"frame\"\r\n\r\n"
#define EPP_CONTENT_POSTFIX_CGI "\r\n----BOUNDARY--\r\n"

/*
 * the implicit HELLO command during a connection open
 */
#define EPP_BUILTIN_HELLO "<epp><hello/></epp>"


typedef struct epp_conn_rec {
    int epp_on;				/* is epp enabled on this server */

    const char *xml_parse_error;
    const char *xml_error_schema;
    const char *command_root;

} epp_conn_rec;

typedef struct epp_user_rec {
    apr_pool_t *pool;

    conn_rec *c;

    char *user;
    char *passwd;
    char *auth_string;

} epp_user_rec;


typedef struct epp_rec {
    apr_pool_t *pool;

    epp_user_rec *ur;
    request_rec *r;
    apr_bucket_brigade *bb_out;

    const char *serialised_xml;
    apr_size_t serialised_xml_size;

    char *orig_xml;
    apr_size_t orig_xml_size;

    apr_xml_doc *doc;
} epp_rec;


int process_epp_connection_internal(request_rec *r, apr_bucket_brigade *bb_in, apr_bucket_brigade *bb_out);

apr_status_t ap_epp_tcp_sendelement(ap_filter_t *f, apr_bucket_brigade *bb, char *e);



#ifdef __cplusplus
}
#endif

#endif	/* EPP_H */
