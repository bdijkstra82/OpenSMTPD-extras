/*      $OpenBSD$   */

/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
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
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	log_debug("debug: on_connect");
	return filter_api_accept(id);
}

static int
on_helo(uint64_t id, const char *helo)
{
	log_debug("debug: on_helo");
	return filter_api_accept(id);
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	log_debug("debug: on_mail");
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
	return filter_api_accept(id);
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
	log_debug("debug: on_dataline");
	filter_api_writeln(id, line);
}

static void
on_reset(uint64_t id)
{
	log_debug("debug: on_reset");
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
}

static void
on_disconnect(uint64_t id)
{
	log_debug("debug: on_disconnect");
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

	filter_api_loop();
	log_debug("debug: exiting");

	return (1);
}
