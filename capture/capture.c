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
#define DEFAULT_SNAPLEN	256
#define DEFAULT_PROMISC	1
#define DEFAULT_TO_MS	1000
static char pcap_errbuf[PCAP_ERRBUF_SIZE];

static VALUE eCaptureError;
static VALUE eTruncatedPacket;
static VALUE cCapture;
static VALUE cFilter;
static VALUE cCaptureStat;

struct filter_object {
	char                *expr;
	struct bpf_program  program;
	int                 datalink;
	int                 snaplen;
	VALUE               optimize;
	VALUE               capture;
	VALUE               netmask;
};

struct capture_object {
  pcap_t		    *pcap;
  pcap_dumper_t *dumper;
	int			      limit;			
  bpf_u_int32	  netmask;
  int			      dl_type;	/* data-link type (DLT_*) */
	VALUE		      dissector;
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

static VALUE capture_close(VALUE self) {
    struct capture_object *cap;

    DEBUG_PRINT("capture_close");
    GetCapture(self, cap);
    
    if (cap->dumper) {
      pcap_dump_close(cap->dumper);
    }

    rb_thread_fd_close(pcap_fileno(cap->pcap));
    pcap_close(cap->pcap);
    cap->pcap = NULL;
    return Qnil;
}

static VALUE capture_setfilter(VALUE self, VALUE v_filter) {
    struct capture_object *cap;
    struct bpf_program program;

    DEBUG_PRINT("capture_setfilter");
    GetCapture(self, cap);

    /* check arg */
	if (IsKindOf(v_filter, cFilter)) {
		struct filter_object *f;
		GetFilter(v_filter, f);
		program = f->program;
	} else {
		Check_Type(v_filter, T_STRING);
		char *filter = RSTRING(v_filter)->ptr;
		
		/* operation */
	    if (pcap_compile(cap->pcap, &program, filter, 1, cap->netmask) < 0)
			rb_raise(eCaptureError, "setfilter: %s", pcap_geterr(cap->pcap));
	}
	
    if (pcap_setfilter(cap->pcap, &program) < 0)
		rb_raise(eCaptureError, "setfilter: %s", pcap_geterr(cap->pcap));
    
    return v_filter;
}


static VALUE capture_setdissector(VALUE self, VALUE dissector) {
	if (!(IsKindOf(dissector, rb_cProc) || dissector == Qnil))
		rb_raise(rb_eArgError, "dissector must be proc or nil");
				
    struct capture_object *cap;
    GetCapture(self, cap);
	
	cap->dissector = dissector;
	
	return dissector;	
}

static VALUE capture_open(int argc, VALUE *argv, VALUE class) {
  VALUE v_device, v_snaplen = Qnil, v_promisc = Qnil, v_to_ms = Qnil, v_filter = Qnil, v_limit = Qnil, v_dissector = Qnil, v_dump = Qnil;
	char *device;
  char *dump;
	int snaplen, promisc, to_ms;
	int rs;
	VALUE self;
	struct capture_object *cap;
	pcap_t *pcap;
	bpf_u_int32 net, netmask;

	DEBUG_PRINT("capture_open_live");

	/* scan arg */
	rs = rb_scan_args(argc, argv, "13", &v_device, &v_snaplen,&v_promisc, &v_to_ms);

	if (IsKindOf(v_device, rb_cHash)) {
		v_snaplen   = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("snapshot_length")));
		v_to_ms     = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("timeout")));
		v_promisc   = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("promiscuous")));
		v_limit     = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("limit")));
		v_filter    = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("filter")));
		v_dissector = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("dissector")));
    v_dump      = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("dump")));
		v_device    = rb_funcall(v_device, rb_intern("[]"), 1, ID2SYM(rb_intern("device")));
		
		if (v_device == Qnil) {
			rb_raise(rb_eArgError, ":device must be specified");
		}
	}
	
	/* device */
	Check_SafeStr(v_device);
	device = RSTRING(v_device)->ptr;

	/* snaplen */
	if (v_snaplen != Qnil) {
		Check_Type(v_snaplen, T_FIXNUM);
		snaplen = FIX2INT(v_snaplen);
	} else {
		snaplen = DEFAULT_SNAPLEN;
	}

	if (snaplen <  0) {
		rb_raise(rb_eArgError, "invalid snaplen");
	}
	
	/* promisc */
	if (v_promisc != Qnil) {
		promisc = RTEST(v_promisc);
	} else {
		promisc = DEFAULT_PROMISC;
	}

	/* to_ms */
	if (v_to_ms != Qnil) {
		Check_Type(v_to_ms, T_FIXNUM);
		to_ms = FIX2INT(v_to_ms);
	} else {
		to_ms = DEFAULT_TO_MS;
	}
		
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
	capture_setdissector(self, v_dissector);

  if (v_dump != Qnil) {
    Check_Type(v_dump, T_STRING);
    cap->dumper = pcap_dump_open(cap->pcap, RSTRING(v_dump)->ptr);
  } else {
    cap->dumper = NULL;
  }
	
	if (v_limit != Qnil) {
		Check_Type(v_limit, T_FIXNUM);
		cap->limit = FIX2INT(v_limit);
	} else {
		cap->limit = -1;
  }
  
	if (v_filter != Qnil) {
		capture_setfilter(self, v_filter);
	}
	
	if (rb_block_given_p()) {
		rb_yield(self);
		capture_close(self);
		return Qnil;
	} else
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

static void handler1(struct capture_object *cap, const struct pcap_pkthdr *pkthdr, const u_char *data) {
	if (cap->dissector != Qnil) {
		VALUE dissected = rb_funcall(cap->dissector, rb_intern("call"), 1, rb_str_new((char *)data, pkthdr->caplen));
		
		rb_yield_values(1, dissected); // not sure why rb_yield doesn't work here, but it wasn't for me
	} else
		rb_yield_values(1, rb_str_new((char *)data, pkthdr->caplen));
}


static void handler2(struct capture_object *cap, const struct pcap_pkthdr *pkthdr, const u_char *data) {
	if (cap->dissector != Qnil) {
		VALUE dissected = rb_funcall(cap->dissector, rb_intern("call"), 1, rb_str_new((char *)data, pkthdr->caplen));

		rb_yield_values(2, dissected, rb_time_new(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec));
	} else
		rb_yield_values(2, rb_str_new((char *)data, pkthdr->caplen), rb_time_new(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec));	
}

static VALUE capture_dispatch(int argc, VALUE *argv, VALUE self) {
	VALUE v_cnt;
	int cnt;
	struct capture_object *cap;
	int ret;

	DEBUG_PRINT("capture_dispatch");
	GetCapture(self, cap);

  if (cap->dumper == NULL) {
    rb_raise(rb_eRuntimeError, "No dump file specified, use each to retrieve packets.");
  }

	/*VALUE proc = rb_block_proc();
	VALUE v_arity = rb_funcall(proc, rb_intern("arity"), 0);
		
	int arity = FIX2INT(v_arity);
  
	pcap_handler handler = (arity < 2) ? (pcap_handler)handler1 : (pcap_handler)handler2;
  */
  
	/* scan arg */
	if (rb_scan_args(argc, argv, "01", &v_cnt) >= 1) {
		FIXNUM_P(v_cnt);
		cnt = FIX2INT(v_cnt);
	} else {
		cnt = -1;
  }
  
	TRAP_BEG;
	ret = pcap_dispatch(cap->pcap, cnt, pcap_dump, (u_char *)cap->dumper);
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

	VALUE proc = rb_block_proc();
	VALUE v_arity = rb_funcall(proc, rb_intern("arity"), 0);
		
	int arity = FIX2INT(v_arity);

	pcap_handler handler = (arity < 2) ? (pcap_handler)handler1 : (pcap_handler)handler2;

  /* scan arg */
	if (rb_scan_args(argc, argv, "01", &v_cnt) >= 1) {
		FIXNUM_P(v_cnt);
		cnt = FIX2INT(v_cnt);
    } else
		cnt = cap->limit;

    if (pcap_file(cap->pcap) != NULL) {
		TRAP_BEG;
		ret = pcap_loop(cap->pcap, cnt, handler, (u_char *)cap);
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

	memset(&stat, 0, sizeof(stat));

    if (pcap_stats(cap->pcap, &stat) == -1)
		return Qnil;

    v_stat = rb_funcall(cCaptureStat, rb_intern("new"), 3,
						UINT2NUM(stat.ps_recv),
						UINT2NUM(stat.ps_drop),
						UINT2NUM(stat.ps_ifdrop));

    return v_stat;
}

static VALUE capture_getlimit(VALUE self) {
    struct capture_object *cap;
    GetCapture(self, cap);
	
	return INT2FIX(cap->limit);
}

static VALUE capture_setlimit(VALUE self, VALUE limit) {
    Check_Type(limit, T_FIXNUM);

	struct capture_object *cap;
    GetCapture(self, cap);
	
	cap->limit = FIX2INT(limit);
	
	return limit;	
}

static VALUE capture_getdissector(VALUE self) {
    struct capture_object *cap;
    GetCapture(self, cap);
	
	return cap->dissector;
}

/*
static VALUE filter_getexpression(VALUE self) {
	struct filter_object *filter;
	
	GetFilter(self, filter);
	return rb_str_new2(filter->expr);
}

static VALUE filter_setexpression(VALUE self, VALUE expression) {
	
	return expression;
}

static VALUE filter_optimize(VALUE self) {
	
	return Qnil;
}

static VALUE filter_or(VALUE self, VALUE other) {
    struct filter_object *filter, *filter2;
    char *expr;

    CheckClass(other, cFilter);
    GetFilter(self, filter);
    GetFilter(other, filter2);

    expr = ALLOCA_N(char, strlen(filter->expr) + strlen(filter2->expr) + 16); 
    sprintf(expr, "( %s ) or ( %s )", filter->expr, filter2->expr);
    return new_filter(expr, filter->capture, filter->optimize, filter->netmask);
}

static VALUE filter_and(VALUE self, VALUE other) {
    struct filter_object *filter, *filter2;
    char *expr;

    CheckClass(other, cFilter);
    GetFilter(self, filter);
    GetFilter(other, filter2);

    expr = ALLOCA_N(char, strlen(filter->expr) + strlen(filter2->expr) + 16); 
    sprintf(expr, "( %s ) and ( %s )", filter->expr, filter2->expr);
    return new_filter(expr, filter->capture, filter->optimize, filter->netmask);
}

static VALUE filter_not(VALUE self) {
    struct filter_object *filter;
    char *expr;

    GetFilter(self, filter);
    expr = ALLOCA_N(char, strlen(filter->expr) + 8); 
    sprintf(expr, "not ( %s )", filter->expr);
    return new_filter(expr, filter->capture, filter->optimize, filter->netmask);
}
*/

void Init_capture() {
	cCapture = rb_define_class("Capture", rb_cObject);
	cFilter = rb_define_class_under(cCapture, "Filter", rb_cObject);

	rb_include_module(cCapture, rb_mEnumerable);	
	rb_define_singleton_method(cCapture, "open", capture_open, -1);
    rb_define_singleton_method(cCapture, "open_offline", capture_open_offline, 1);
    rb_define_method(cCapture, "close", capture_close, 0);
    rb_define_method(cCapture, "dispatch", capture_dispatch, -1);
    rb_define_method(cCapture, "each", capture_loop, -1);
    rb_define_method(cCapture, "each_packet", capture_loop, -1);
    rb_define_method(cCapture, "filter=", capture_setfilter, 1);
	rb_define_method(cCapture, "limit", capture_getlimit, 0);
	rb_define_method(cCapture, "limit=", capture_setlimit, 1);
	rb_define_method(cCapture, "dissector", capture_getdissector, 0);
	rb_define_method(cCapture, "dissector=", capture_setdissector, 0);
    rb_define_method(cCapture, "datalink", capture_datalink, 0);
	rb_define_method(cCapture, "snapshot_length", capture_snapshot, 0);
    rb_define_method(cCapture, "stats", capture_stats, 0);

	/*
	rb_define_method(cFilter, "expression", filter_getexpression, 0);
	rb_define_method(cFilter, "expression=", filter_setexpression, 1);
	rb_define_method(cFilter, "optimize!", filter_optimize, 0);
    rb_define_method(cFilter, "|", filter_or, 1);
    rb_define_method(cFilter, "&", filter_and, 1);
    rb_define_method(cFilter, "~@", filter_not, 0);
	*/
	
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
