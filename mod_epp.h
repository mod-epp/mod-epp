
#ifndef EPP_H
#define EPP_H

#include "apr.h"
#include "httpd.h"
#include "util_filter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EPP_TCP_HEADER_SIZE 4		/* just one longword */
#define EPP_CHUNK_SIZE 2048		/* try to read that many bytes at once */
#define EPP_MAX_FRAME_SIZE 65536	/* don't accept larger xml data blocks */
#define TRIDSIZE 128			/* actually, it should be 3 to 64 chars,
					   but due to unicode we'll give it more room. */

#define CLIDSIZE 32
/*
 *    <simpleType name="clIDType">
 *       <restriction base="token">
 *          <minLength value="3"/>
 *          <maxLength value="16"/>
 *       </restriction>
 *    </simpleType>
 */ 
#define PWSIZE 32
/*
 *     <simpleType name="pwType">
 *        <restriction base="token">
 *           <minLength value="6"/>
 *           <maxLength value="16"/>
 *        </restriction>
 *     </simpleType>
 */                                     


module AP_MODULE_DECLARE_DATA epp_module;

#define EPP_DEFAULT_XML_ERROR "/epp/error/xmlparsing"
#define EPP_DEFAULT_XML_ERROR_SCHEMA "/epp/error/schema"
#define EPP_DEFAULT_ERROR_PROTOCOL "/epp/error/protocol"
#define EPP_DEFAULT_COMMAND_ROOT "/epp/command"
#define EPP_DEFAULT_SESSION_ROOT "/epp/session"
#define EPP_DEFAULT_ERROR_ROOT "/epp/error"

#define EPP_CONTENT_TYPE_CGI "multipart/form-data; boundary=--BOUNDARY--"
#define EPP_CONTENT_FRAME_CGI "----BOUNDARY--\r\nContent-Disposition: form-data; name=\"frame\"\r\n\r\n"
#define EPP_CONTENT_CLTRID_CGI "\r\n----BOUNDARY--\r\nContent-Disposition: form-data; name=\"clTRID\"\r\n\r\n"
#define EPP_CONTENT_POSTFIX_CGI "\r\n----BOUNDARY--\r\n"

/*
 * the implicit HELLO command during a connection open
 */
#define EPP_BUILTIN_HELLO "<epp><hello/></epp>"

/*
 * Translate a timeout into:
 */
#define EPP_BUILTIN_TIMEOUT "<epp><timeout/></epp>"

/*
 * the implicit HELLO command during a connection open
 */
#define EPP_BUILTIN_ERROR_HEAD "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"  xsi:schemaLocation=\"urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd\">" 

/*
 * some return codes
 */
#define EPP_PROT_ERROR 1
#define EPP_PROT_OK 0




typedef struct epp_conn_rec {
    int epp_on;				/* is epp enabled on this server */

    char *xml_error_parse;
    char *xml_error_schema;
    char *error_protocol;
    const char *command_root;
    const char *session_root;
    const char *error_root;
    const char *authuri;

} epp_conn_rec;

typedef struct epp_user_rec {
    apr_pool_t *pool;
    epp_conn_rec *conf;

    conn_rec *c;

    char clid[CLIDSIZE];
    char pw[PWSIZE];
    char *auth_string;

    int authenticated;
    int failed_logins;

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

    char cltrid[TRIDSIZE];

} epp_rec;

apr_status_t epp_error_handler(epp_rec *er, char *script, int code, char *cltrid, char *errmsg);


#ifdef __cplusplus
}
#endif

#endif	/* EPP_H */
