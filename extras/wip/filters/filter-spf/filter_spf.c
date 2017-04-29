/*
 * Copyright (c) 2016 Boudewijn Dijkstra <boudewijn@ndva.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"
#include "spf.h"

extern const char *
ss_to_text(const struct sockaddr_storage *ss);

#define MAXMAIL  (SMTPD_MAXLOCALPARTSIZE + SMTPD_MAXDOMAINPARTSIZE)

struct envelope {
	int state;	/* number of other fields filled in, 0..4 */
	struct sockaddr_storage remote;
	char helo[SMTPD_MAXHOSTNAMELEN];
	char from[MAXMAIL];
	char prepend_line[SMTPD_MAXLINESIZE];
};

static int 		 vflag;
static SPF_server_t	*spf_server;
static int enforce = 0;

static struct envelope *
envelope(uint64_t id, int create)
{
	struct envelope *p;

	p = filter_api_get_udata(id);
	if (p == NULL && create) {
		p = xmalloc(sizeof(struct envelope), "msg");
		p->state = 0;
		filter_api_set_udata(id, p);
	}
	return p;
}

static int
spfcheck(uint64_t id, SPF_result_t *out_result, char *out_comment)
{
	struct envelope *msg;
	SPF_request_t	*spf_request;
	SPF_errcode_t	 spf_errcode;
	SPF_response_t	*spf_response = NULL;
	SPF_result_t	 spf_result = SPF_RESULT_INVALID;
	SPF_reason_t 	 spf_reason;
	struct sockaddr_storage *ss;
	const char 	*ln;

	msg = envelope(id, 0);
	if (msg == NULL || msg->state != 3) {
		if (msg) {
			log_debug("debug: unexpected state: %d", msg->state);
		} else {
			log_debug("debig: unexpected state: msg is NULL");
		}
		return -1;
	}

	spf_request = SPF_request_new(spf_server);
	spf_errcode = spf_request ? SPF_E_SUCCESS : SPF_E_NO_MEMORY;

	if (spf_errcode == SPF_E_SUCCESS) {
		ss = &msg->remote;
		if (ss->ss_family == AF_INET)
			spf_errcode = SPF_request_set_ipv4(spf_request, 
				((const struct sockaddr_in *)ss)->sin_addr);
		else /* AF_INET6 */
			spf_errcode = SPF_request_set_ipv6(spf_request, 
				((const struct sockaddr_in6 *)ss)->sin6_addr);
	}

	if (spf_errcode == SPF_E_SUCCESS)
		spf_errcode = SPF_request_set_helo_dom(spf_request, msg->helo);

	if (spf_errcode == SPF_E_SUCCESS)
		spf_errcode = SPF_request_set_env_from(spf_request, msg->from);

	if (spf_errcode == SPF_E_SUCCESS)
		spf_errcode = SPF_request_query_mailfrom(spf_request,
								&spf_response);
	log_debug("debug: spf_record_exp: %x", 
					(uint32_t)spf_response->spf_record_exp);

	if (spf_errcode != SPF_E_NO_MEMORY) {
		spf_result = SPF_response_result(spf_response);
		spf_reason = SPF_response_reason(spf_response);
		log_debug("debug: spf: error=%s", SPF_strerror(spf_errcode));
		log_debug("debug: spf: result=%s", SPF_strresult(spf_result));
		log_debug("debug: spf: reason=%s", SPF_strreason(spf_reason));
		if (spf_response->spf_record_exp != NULL || (
				spf_result == SPF_RESULT_PASS ||
				spf_result == SPF_RESULT_INVALID ||
				spf_result == SPF_RESULT_TEMPERROR ||
				spf_result == SPF_RESULT_PERMERROR)) 
			spf_errcode = SPF_i_done(spf_response, spf_result, 
						spf_reason, spf_errcode);
	}

	ln = SPF_response_get_received_spf(spf_response);
	log_debug("debug: spf: %s", ln);
	if (ln)
		strncpy(msg->prepend_line, ln, SMTPD_MAXLINESIZE);
	else
		snprintf(msg->prepend_line, SMTPD_MAXLINESIZE, 
			"Received-SPF: none (%s)", SPF_strerror(spf_errcode));
	msg->state++;

	const char *comment = SPF_response_get_smtp_comment(spf_response);
	if (comment) {
		log_debug("debug: smtp comment: %s", comment);
		strncpy(out_comment, comment, SMTPD_MAXLINESIZE);
	} else {
		snprintf(out_comment, SMTPD_MAXLINESIZE, "SPF Check failed");
	}
	*out_result = spf_result;

	SPF_response_free(spf_response);
	SPF_request_free(spf_request);
	return spf_errcode;
}

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	struct envelope *msg;

	log_debug("debug: on_connect");
	msg = envelope(id, 1);
	memcpy(&msg->remote, &conn->remote, sizeof(struct sockaddr_storage));
	msg->state = 1;
	return filter_api_accept(id);
}

static int
on_helo(uint64_t id, const char *helo)
{
	struct envelope *msg;

	log_debug("debug: on_helo");
	msg = envelope(id, 1);
	strlcpy((char *)msg->helo, helo, SMTPD_MAXHOSTNAMELEN);
	msg->state = 2;
	return filter_api_accept(id);
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	struct envelope *msg;

	log_debug("debug: on_mail");
	msg = envelope(id, 1);
	if (strlen(mail->user) || strlen(mail->domain)) {
		snprintf(msg->from, MAXMAIL, "%s@%s", mail->user, mail->domain);
	} else {
		// A bounce
		msg->from[0] = '\0';
	}
	msg->state = 3;
	return filter_api_accept(id);
}

static int
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	log_debug("debug: on_rcpt");
	return filter_api_accept(id);
}

static int
on_data(uint64_t id)
{
	struct envelope *msg;
	SPF_result_t result;
	char comment[SMTPD_MAXLINESIZE + 1];
	comment[SMTPD_MAXLINESIZE] = '\0';

	log_debug("debug: on_data");
	msg = envelope(id, 0);
	if (msg != NULL) {
//		log_debug("debug: msg.remote = %s", ss_to_text(&msg->remote));
		log_debug("debug: msg.helo = %s", msg->helo);
		log_debug("debug: msg.from = %s", msg->from);
	}
	spfcheck(id, &result, comment);

	if (enforce && (
		    result == SPF_RESULT_FAIL || result == SPF_RESULT_PERMERROR
                 || result == SPF_RESULT_TEMPERROR)) {
		int code = result == SPF_RESULT_TEMPERROR ? 451 : 550;

		return filter_api_reject_code(id, FILTER_FAIL, code, comment);
	} else {
		return filter_api_accept(id);
	}
}

static int
on_eom(uint64_t id, size_t size)
{
	log_debug("debug: on_eom");
	return filter_api_accept(id);
}

static void
on_dataline(uint64_t id, const char *line)
{
	struct envelope *msg;

	msg = envelope(id, 0);
	if (msg != NULL && msg->state == 4) {
		log_debug("debug: on_dataline[0]");
		filter_api_writeln(id, msg->prepend_line);
		/* we may get another message on the same session */
		msg->state = 2;
		msg->from[0] = '\0';
		msg->prepend_line[0] = '\0';
	} else if (msg == NULL)
		log_debug("debug: on_dataline: msg NULL");
	else if (msg->state != 2)
		log_debug("debug: on_dataline: state %d", msg->state);
	filter_api_writeln(id, line);
}

static void
on_reset(uint64_t id)
{
	struct envelope *msg;

	log_debug("debug: on_reset");
	msg = envelope(id, 0);
	if (msg != NULL) {
		if (msg->state > 2)
			msg->state = 2;
		msg->from[0] = '\0';
		msg->prepend_line[0] = '\0';
	}
}

static void
on_commit(uint64_t id)
{
	log_debug("debug: on_commit");
}

static void
on_rollback(uint64_t id)
{
	struct envelope *msg;

	log_debug("debug: on_rollback");
	msg = envelope(id, 0);
	if (msg != NULL) {
		if (msg->state > 2)
			msg->state = 2;
		msg->from[0] = '\0';
		msg->prepend_line[0] = '\0';
	}
}

static void
on_disconnect(uint64_t id)
{
	log_debug("debug: on_disconnect");
	filter_api_set_udata(id, NULL);
}

int
main(int argc, char **argv)
{
	int	ch, d = 0, v = 0;

	log_init(1);

	while ((ch = getopt(argc, argv, "dev")) != -1) {
		switch (ch) {
		case 'd':
			d = 1;
			break;
		case 'e':
			enforce = 1;
			break;
		case 'v':
			v |= TRACE_DEBUG;
			vflag++;
			break;
		default:
			log_warnx("warn: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");
	spf_server = SPF_server_new(SPF_DNS_CACHE, 0);

	filter_api_on_connect(on_connect);
	filter_api_on_helo(on_helo);
	filter_api_on_mail(on_mail);
	filter_api_on_rcpt(on_rcpt);
	filter_api_on_data(on_data);
	filter_api_on_reset(on_reset);
	filter_api_on_eom(on_eom);
	filter_api_on_dataline(on_dataline);
	filter_api_on_commit(on_commit);
	filter_api_on_rollback(on_rollback);
	filter_api_on_disconnect(on_disconnect);

	filter_api_no_chroot();
	filter_api_loop();
	log_debug("debug: exiting");
	SPF_server_free(spf_server);

	return (1);
}
