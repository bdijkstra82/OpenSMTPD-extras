EXTRAS_PATH=	${.CURDIR}/../OpenSMTPD-extras
BINDIR=	/usr/local/libexec/smtpd
PROG=	filter-spf
MAN=    filter-spf.8
SRCS=	filter_spf.c

.PATH: ${EXTRAS_PATH}/api
SRCS+=  filter_api.c
SRCS+=  iobuf.c ioev.c log.c mproc.c tree.c util.c to.c

CFLAGS+= -Wall -Wstrict-prototypes -I${.CURDIR} \
	-I/usr/local/include/spf2 -I/usr/local/include/bind \
	-I${EXTRAS_PATH}/ \
	-I${EXTRAS_PATH}/api \
	-I${EXTRAS_PATH}/openbsd-compat \
	-DHAVE___B64_NTOP -DHAVE___B64_PTON

LDADD=	-lutil -levent -lbind -lspf2
LDFLAGS+=	-L/usr/local/lib -L/usr/local/lib/libbind
DPADD=  ${LIBUTIL} ${LIBEVENT}	\
	/usr/local/lib/libspf2.a \
	/usr/local/lib/libbind/libbind.a

.include <bsd.prog.mk>
