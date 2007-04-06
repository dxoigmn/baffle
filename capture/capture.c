/* Based heavily on http://www.goto.info.waseda.ac.jp/~fukusima/ruby/pcap-e.html 
 * But simplified because we already do a lot of what that did elsewhere
 *
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>

#include <pcap.h>

#include "ruby.h"
#include "rubysig.h"

#define DEFAULT_DATALINK	DLT_EN10MB
#define DEFAULT_SNAPLEN	68
#define DEFAULT_PROMISC	1
#define DEFAULT_TO_MS	1000
static char pcap_errbuf[PCAP_ERRBUF_SIZE];

static VALUE eCaptureError;
static VALUE eTruncatedPacket;
static VALUE cCapture;
static VALUE cFilter;
static VALUE cCaptureStat;

struct filter_object {
	char *expr;
	struct bpf_program program;
	int datalink;
	int snaplen;
	VALUE param;
	VALUE optimize;
	VALUE netmask;
};

struct capture_object {
    pcap_t		*pcap;
    bpf_u_int32	netmask;
    int			dl_type;	/* data-link type (DLT_*) */
};

#define GetFilter(obj, filter) Data_Get_Struct(obj, struct filter_object, filter)
#define GetPacket(obj, pkt) Data_Get_Struct(obj, struct packet_object, pkt)
#define GetCapture(obj, cap) {\
    Data_Get_Struct(obj, struct capture_object, cap);\
    if (cap->pcap == NULL) closed_capture();\
}
#define Caplen(pkt, from) ((pkt)->hdr.pkthdr.caplen - (from))
#define CheckTruncate(pkt, from, need, emsg) (\
    (from) + (need) > (pkt)->hdr.pkthdr.caplen ? \
        rb_raise(eTruncatedPacket, (emsg)) : 0 \
)

#define IsKindOf(v, class) RTEST(rb_obj_is_kind_of(v, class))
#define CheckClass(v, class) ((IsKindOf(v, class)) ? 0 :\
    rb_raise(rb_eTypeError, "wrong type %s (expected %s)",\
        rb_class2name(CLASS_OF(v)), rb_class2name(class)))

#ifdef DEBUG
# define DEBUG_PRINT(x) \
    ((RTEST(ruby_debug) && RTEST(ruby_verbose))?\
    (fprintf(stderr, "%s\n", x),fflush(stderr)) : 0)
#else
# define DEBUG_PRINT(x) (0)
#endif

static void	closed_capture() {
    rb_raise(rb_eRuntimeError, "device is already closed");
}

/* called from GC */
static void free_capture(struct capture_object *cap) {
	DEBUG_PRINT("free_capture");
	if (cap->pcap != NULL) {
		DEBUG_PRINT("closing capture");
		rb_thread_fd_close(pcap_fileno(cap->pcap));
		pcap_close(cap->pcap);
		cap->pcap = NULL;
	}
	free(cap);
}

static VALUE capture_open_live(int argc, VALUE *argv, VALUE class) {
	VALUE v_device, v_snaplen, v_promisc, v_to_ms;
	char *device;
	int snaplen, promisc, to_ms;
	int rs;
	VALUE self;
	struct capture_object *cap;
	pcap_t *pcap;
	bpf_u_int32 net, netmask;

	DEBUG_PRINT("capture_open_live");

	/* scan arg */
	rs = rb_scan_args(argc, argv, "13", &v_device, &v_snaplen,
		&v_promisc, &v_to_ms);

	/* device */
	Check_SafeStr(v_device);
	device = RSTRING(v_device)->ptr;
	
	/* snaplen */
	if (rs >= 2) {
		Check_Type(v_snaplen, T_FIXNUM);
		snaplen = FIX2INT(v_snaplen);
	} else {
		snaplen = DEFAULT_SNAPLEN;
	}
	
	if (snaplen <  0)
		rb_raise(rb_eArgError, "invalid snaplen");
		
	/* promisc */
	if (rs >= 3) {
		promisc = RTEST(v_promisc);
	} else {
		promisc = DEFAULT_PROMISC;
	}

	/* to_ms */
	if (rs >= 4) {
		Check_Type(v_to_ms, T_FIXNUM);
		to_ms = FIX2INT(v_to_ms);
	} else
		to_ms = DEFAULT_TO_MS;

	/* open */
	pcap = pcap_open_live(device, snaplen, promisc, to_ms, pcap_errbuf);
	if (pcap == NULL) {
		rb_raise(eCaptureError, "%s", pcap_errbuf);
	}
	if (pcap_lookupnet(device, &net, &netmask, pcap_errbuf) == -1) {
		netmask = 0;
		rb_warning("cannot lookup net: %s\n", pcap_errbuf);
	}

	/* setup instance */
	self = Data_Make_Struct(class, struct capture_object, 0, free_capture, cap);
	cap->pcap = pcap;
	cap->netmask = netmask;
	cap->dl_type = pcap_datalink(pcap);

	return self;
}

static VALUE capture_open_offline(VALUE class, VALUE fname) {
	VALUE self;
	struct capture_object *cap;
	pcap_t *pcap;

	DEBUG_PRINT("capture_open_offline");

	/* open offline */
	Check_SafeStr(fname);
	pcap = pcap_open_offline(RSTRING(fname)->ptr, pcap_errbuf);
	if (pcap == NULL) {
		rb_raise(eCaptureError, "%s", pcap_errbuf);
	}

	/* setup instance */
	self = Data_Make_Struct(class, struct capture_object, 0, free_capture, cap);
	cap->pcap = pcap;
	cap->netmask = 0;
	cap->dl_type = pcap_datalink(pcap);

	return self;
}

static VALUE capture_close(VALUE self) {
    struct capture_object *cap;

    DEBUG_PRINT("capture_close");
    GetCapture(self, cap);

    rb_thread_fd_close(pcap_fileno(cap->pcap));
    pcap_close(cap->pcap);
    cap->pcap = NULL;
    return Qnil;
}

static void handler(struct capture_object *cap, const struct pcap_pkthdr *pkthdr, const u_char *data) {
	// Do I need to copy? I think so
	char *data_copy = xmalloc(pkthdr->caplen);
	memcpy(data_copy, data, pkthdr->caplen);
	rb_yield(rb_str_new(data_copy, pkthdr->caplen));
}

static VALUE capture_dispatch(int argc, VALUE *argv, VALUE self) {
	VALUE v_cnt;
	int cnt;
	struct capture_object *cap;
	int ret;

	DEBUG_PRINT("capture_dispatch");
	GetCapture(self, cap);


	/* scan arg */
	if (rb_scan_args(argc, argv, "01", &v_cnt) >= 1) {
		FIXNUM_P(v_cnt);
		cnt = FIX2INT(v_cnt);
	} else
		cnt = -1;

	TRAP_BEG;
	ret = pcap_dispatch(cap->pcap, cnt, (pcap_handler)handler, (u_char *)cap);
	TRAP_END;
	
	if (ret == -1)
		rb_raise(eCaptureError, "dispatch: %s", pcap_geterr(cap->pcap));

	return INT2FIX(ret);
}

static VALUE capture_loop(int argc, VALUE *argv, VALUE self) {
    VALUE v_cnt;
    int cnt;
    struct capture_object *cap;
    int ret;

    DEBUG_PRINT("capture_loop");
    GetCapture(self, cap);

    /* scan arg */
	if (rb_scan_args(argc, argv, "01", &v_cnt) >= 1) {
		FIXNUM_P(v_cnt);
		cnt = FIX2INT(v_cnt);
    } else
		cnt = -1;

    if (pcap_file(cap->pcap) != NULL) {
		TRAP_BEG;
		ret = pcap_loop(cap->pcap, cnt, (pcap_handler)handler, (u_char *)cap);
		TRAP_END;
	} else {
		int fd = pcap_fileno(cap->pcap);
		fd_set rset;
		struct timeval tm;

		FD_ZERO(&rset);
		tm.tv_sec = 0;
		tm.tv_usec = 0;
		for (;;) {
			do {
				FD_SET(fd, &rset);
				if (select(fd+1, &rset, NULL, NULL, &tm) == 0) {
					rb_thread_wait_fd(fd);
				}
				TRAP_BEG;
				ret = pcap_read(cap->pcap, 1, handler, (u_char *)cap);
				TRAP_END;
			} while (ret == 0);
			if (ret <= 0)
				break;
			if (cnt > 0) {
				cnt -= ret;
				if (cnt <= 0)
					break;
			}
		}
	}

    return INT2FIX(ret);
}

static VALUE capture_setfilter(int argc, VALUE *argv, VALUE self) {
    struct capture_object *cap;
    VALUE vfilter, optimize;
    char *filter;
    int opt;
    struct bpf_program program;

    DEBUG_PRINT("capture_setfilter");
    GetCapture(self, cap);

    /* scan arg */
    if (rb_scan_args(argc, argv, "11", &vfilter, &optimize) == 1)
		optimize = Qtrue;

    /* check arg */
	if (IsKindOf(vfilter, cFilter)) {
		struct filter_object *f;
		GetFilter(vfilter, f);
		filter = f->expr;
	} else {
		Check_Type(vfilter, T_STRING);
		filter = RSTRING(vfilter)->ptr;
	}
	opt = RTEST(optimize);

    /* operation */
    if (pcap_compile(cap->pcap, &program, filter,
		     opt, cap->netmask) < 0)
		
	rb_raise(eCaptureError, "setfilter: %s", pcap_geterr(cap->pcap));
	
    if (pcap_setfilter(cap->pcap, &program) < 0)
		rb_raise(eCaptureError, "setfilter: %s", pcap_geterr(cap->pcap));
    
    return Qnil;
}

static VALUE capture_datalink(VALUE self) {
    struct capture_object *cap;

    DEBUG_PRINT("capture_datalink");
    GetCapture(self, cap);

    return INT2NUM(pcap_datalink(cap->pcap));
}

static VALUE capture_snapshot(VALUE self) {
    struct capture_object *cap;

    DEBUG_PRINT("capture_snapshot");
    GetCapture(self, cap);

    return INT2NUM(pcap_snapshot(cap->pcap));
}

static VALUE capture_stats(VALUE self) {
    struct capture_object *cap;
    struct pcap_stat stat;
    VALUE v_stat;

    DEBUG_PRINT("capture_stats");
    GetCapture(self, cap);

    if (pcap_stats(cap->pcap, &stat) == -1)
		return Qnil;

    v_stat = rb_funcall(cCaptureStat, rb_intern("new"), 3,
						UINT2NUM(stat.ps_recv),
						UINT2NUM(stat.ps_drop),
						UINT2NUM(stat.ps_ifdrop));

    return v_stat;
}

void Init_capture() {
	cCapture = rb_define_class("Capture", rb_cObject);
	cFilter = rb_define_class_under(cCapture, "Filter", rb_cObject);

	rb_include_module(cCapture, rb_mEnumerable);	
	rb_define_singleton_method(cCapture, "open_live", capture_open_live, -1);
    rb_define_singleton_method(cCapture, "open_offline", capture_open_offline, 1);
    rb_define_method(cCapture, "close", capture_close, 0);
    rb_define_method(cCapture, "dispatch", capture_dispatch, -1);
    rb_define_method(cCapture, "each_packet", capture_loop, -1);
    rb_define_method(cCapture, "setfilter", capture_setfilter, -1);
    rb_define_method(cCapture, "datalink", capture_datalink, 0);
    rb_define_method(cCapture, "snapshot", capture_snapshot, 0);
    rb_define_method(cCapture, "snaplen", capture_snapshot, 0);
    rb_define_method(cCapture, "stats", capture_stats, 0);

    cCaptureStat = rb_funcall(rb_cStruct, rb_intern("new"), 4,
			   	   Qnil,
				   ID2SYM(rb_intern("recv")),
				   ID2SYM(rb_intern("drop")),
				   ID2SYM(rb_intern("ifdrop")));
    rb_define_const(cCapture, "Stat", cCaptureStat);

    /* define exception classes */
    eCaptureError    = rb_define_class_under(cCapture, "CaptureError", rb_eStandardError);
    eTruncatedPacket = rb_define_class_under(cCapture, "TruncatedPacket", eCaptureError);
}