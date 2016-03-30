/*      $OpenBSD$   */

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
	struct sockaddr_storage remote;
	char helo[SMTPD_MAXHOSTNAMELEN];
	char from[MAXMAIL];
	char prepend_line[SMTPD_MAXLINESIZE];
};

static int 		 vflag;
static int 		 first_line = 1;
static int 		 in_hdrs = 1;
static SPF_server_t	*spf_server;	/* XXX thread-safe? */

static struct envelope *
envelope(uint64_t id)
{
	struct envelope *p;

	p = filter_api_get_udata(id);
	if (p == NULL) {
		p = xmalloc(sizeof(struct envelope), "msg");
		p->remote.ss_family = 0;
		p->helo[0] = '\0';
		p->from[0] = '\0';
		p->prepend_line[0] = '\0';
		filter_api_set_udata(id, p);
	}
	return p;
}

static int
spfcheck(uint64_t id)
{
	SPF_request_t	*spf_request;
	SPF_errcode_t	 spf_errcode;
	SPF_response_t	*spf_response = NULL;
	SPF_result_t	 spf_result = SPF_RESULT_INVALID;
	SPF_reason_t 	 spf_reason;
	struct sockaddr_storage *ss;
	const char 	*ln;
	struct envelope *msg = envelope(id);

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
	log_debug("debug: spf_record_exp: %x", (uint32_t)spf_response->spf_record_exp);

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

	SPF_response_free(spf_response);
	SPF_request_free(spf_request);
	return spf_errcode;
}

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	log_debug("debug: on_connect");
	struct envelope *msg = envelope(id);

	memcpy(&msg->remote, &conn->remote, sizeof(struct sockaddr_storage));
	return filter_api_accept(id);
}

static int
on_helo(uint64_t id, const char *helo)
{
	log_debug("debug: on_helo");
	struct envelope *msg = envelope(id);
	strlcpy((char *)msg->helo, helo, SMTPD_MAXHOSTNAMELEN);
	return filter_api_accept(id);
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	log_debug("debug: on_mail");
	struct envelope *msg = envelope(id);
	snprintf(msg->from, MAXMAIL, "%s@%s", mail->user, mail->domain);
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
	log_debug("debug: on_data");
	struct envelope *msg = envelope(id);
	log_debug("debug: msg.remote = %s", ss_to_text(&msg->remote));
	log_debug("debug: msg.helo = %s", msg->helo);
	log_debug("debug: msg.from = %s", msg->from);
	spfcheck(id);
	return filter_api_accept(id);
}

static int
on_eom(uint64_t id, size_t size)
{
	log_debug("debug: on_eom");
	struct envelope *msg = envelope(id);
	msg->from[0] = '\0';
	first_line = 1;
	return filter_api_accept(id);
}

static void
on_dataline(uint64_t id, const char *line)
{
	log_debug("debug: on_dataline");
	struct envelope *msg = envelope(id);
	if (in_hdrs && line[0] == '\0')
		in_hdrs = 0;
	if (first_line) {
		first_line = 0;
		if (msg->prepend_line[0]) {
			filter_api_writeln(id, msg->prepend_line);
			msg->prepend_line[0] = '\0';
		}
	}
	filter_api_writeln(id, line);
}

static void
on_reset(uint64_t id)
{
	log_debug("debug: on_reset");
	filter_api_set_udata(id, NULL);
}

static void
on_commit(uint64_t id)
{
	log_debug("debug: on_commit");
}

static void
on_rollback(uint64_t id)
{
	log_debug("debug: on_rollback");
	filter_api_set_udata(id, NULL);
}

static void
on_disconnect(uint64_t id)
{
	log_debug("debug: on_disconnect");
	struct envelope *msg = envelope(id);
	msg->remote.ss_family = 0;
	msg->helo[0] = '\0';
	first_line = 1;
	filter_api_set_udata(id, NULL);
}

int
main(int argc, char **argv)
{
	int	ch, d = 0, v = 0;

	log_init(1);

	while ((ch = getopt(argc, argv, "dv")) != -1) {
		switch (ch) {
		case 'd':
			d = 1;
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
