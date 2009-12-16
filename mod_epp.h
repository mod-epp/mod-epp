/*
 * Copyright (c) 2002 NIC.at Internet Verwaltungs- und 
 * Betriebsgesellschaft m. b. H. All rights reserved.
 *
 * Written by Otmar Lendl <lendl@nic.at>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *        "This product includes software developed by the
 *        NIC.at Internet Verwaltungs- und Betriebsgesellschaft m. b. H."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "mod_epp" and "NIC.at" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact lendl@nic.at
 *
 * 5. Products derived from this software may not be called "mod_epp",
 *    nor may "mod_epp" appear in their name, without prior written
 *    permission of NIC.at.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL NIC.AT INTERNET VERWALTUNGS- UND
 * BETRIEBSGESELLSCHAFT M.B.H. OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef EPP_H
#define EPP_H

#include "apr.h"
#include "httpd.h"
#include "util_filter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EPP_TCP_HEADER_SIZE 4		/* just one longword */
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
#define EPP_DEFAULT_AUTH_URI "/epp/auth"
#define EPP_DEFAULT_RC_HEADER "X-EPP-Returncode"


#define EPP_CONTENT_TYPE_CGI "multipart/form-data; boundary=--BOUNDARY--"
#define EPP_CONTENT_FRAME_CGI "----BOUNDARY--\r\nContent-Disposition: form-data; name=\"frame\"\r\n\r\n"
#define EPP_CONTENT_CLTRID_CGI "\r\n----BOUNDARY--\r\nContent-Disposition: form-data; name=\"clTRID\"\r\n\r\n"
#define EPP_CONTENT_POSTFIX_CGI "\r\n----BOUNDARY--\r\n"

/*
 * the implicit HELLO command during a connection open
 */
#define EPP_BUILTIN_HELLO "<?xml+version=\"1.0\"+encoding=\"UTF-8\"+standalone=\"no\"?><epp+xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><hello/></epp>"


/*
 * Use this prefix in front of every self-generated error message
 */
#define EPP_BUILTIN_ERROR_HEAD "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"  xsi:schemaLocation=\"urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd\">" 

/*
 * Use the following as HTTP User-agent
 */
#define EPP_USER_AGENT "mod_epp/1.6 +https://sourceforge.net/projects/aepps/"

/*
 * some return codes
 */
#define EPP_PROT_ERROR 1
#define EPP_PROT_OK 0




typedef struct epp_conn_rec {
    int epp_on;				/* is epp enabled on this server */

    int implicit_login;			/* is authentication done with <login> ? */
    char *xml_error_parse;
    char *xml_error_schema;
    char *error_protocol;
    const char *command_root;
    const char *session_root;
    const char *error_root;
    const char *authuri;
    const char *rc_header;

} epp_conn_rec;

typedef struct epp_user_rec {
    apr_pool_t *pool;
    epp_conn_rec *conf;

    conn_rec *c;

    char *auth_string;
    char clid[CLIDSIZE];
    char pw[PWSIZE];
    char cookie[41]; 		/* session=MD5-hash  thus: 8 + (MD5_DIGESTSIZE * 2) + 1 */

    int authenticated;
    int connection_close;	/* did a script signal Connection: close ? */
    int failed_logins;


/* give the filter a chance to find the current request object */
    struct epp_rec *er;	

} epp_user_rec;


typedef struct epp_rec {
    apr_pool_t *pool;

    epp_user_rec *ur;
    request_rec *r;
    apr_bucket_brigade *bb_out;
    apr_bucket_brigade *bb_tmp;

    const char *serialised_xml;
    apr_size_t serialised_xml_size;

    char *orig_xml;
    apr_size_t orig_xml_size;

    apr_xml_doc *doc;

    char cltrid[TRIDSIZE];

} epp_rec;

/* Function prototypes */

apr_status_t epp_error_handler(epp_rec *er, char *script, int code, char *cltrid, char *errmsg);

void epp_make_cookie(epp_user_rec *ur);
char *get_attr(apr_xml_attr *attr, const char *name);
apr_xml_elem *get_elem(apr_xml_elem *elem, const char *name);
void xml_firstcdata_strncat(char *dest, size_t dstsize, apr_xml_elem *elem);
apr_status_t epp_get_cltrid(epp_rec *er);
apr_status_t epp_login(epp_rec *er, apr_xml_elem *login);
apr_status_t epp_logout(epp_rec *er, apr_xml_elem *login);
void epp_process_frame(epp_rec *er);
apr_status_t epp_do_hello(epp_rec *er);
apr_status_t epp_read(conn_rec *c, apr_pool_t *p, char *buf, apr_size_t count);
apr_status_t epp_translate_xml_to_uri(apr_xml_doc *doc, epp_rec *er,
                char *path, apr_size_t path_size, apr_xml_elem **element, int *login_needed);

int epp_dump_table_entry(void *rec, const char *key, const char *value);
void epp_dump_table(apr_table_t *t, const char *s);


#ifdef __cplusplus
}
#endif

#endif	/* EPP_H */

