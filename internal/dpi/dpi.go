// Package dpi wraps the nDPI deep packet inspection library.
//
// An Engine and the FlowStates created from it are not safe for concurrent
// use; the whole pipeline is expected to run on a single goroutine.
package dpi

/*
#cgo CFLAGS: -I/usr/include/ndpi
#cgo LDFLAGS: -L/usr/lib -l:libndpi.a -lm -ldl -lpthread
#include <stdlib.h>
#include <string.h>
#include <ndpi_api.h>

typedef struct {
	u_int16_t master;
	u_int16_t app;
	u_int16_t category;
	u_int8_t state;
} router_result;

static router_result router_convert(ndpi_protocol p) {
	router_result r;
	r.master = p.proto.master_protocol;
	r.app = p.proto.app_protocol;
	r.category = (u_int16_t)p.category;
	r.state = (u_int8_t)p.state;
	return r;
}

static struct ndpi_flow_struct *router_flow_alloc(void) {
	u_int32_t size = ndpi_detection_get_sizeof_ndpi_flow_struct();
	struct ndpi_flow_struct *f = ndpi_flow_malloc(size);
	if (f != NULL)
		memset(f, 0, size);
	return f;
}

static router_result router_process(struct ndpi_detection_module_struct *mod,
                                    struct ndpi_flow_struct *flow,
                                    const unsigned char *pkt, unsigned short len,
                                    u_int64_t ts_ms) {
	struct ndpi_flow_input_info info;
	memset(&info, 0, sizeof(info));
	info.in_pkt_dir = NDPI_IN_PKT_DIR_UNKNOWN;
	info.seen_flow_beginning = NDPI_FLOW_BEGINNING_UNKNOWN;
	return router_convert(ndpi_detection_process_packet(mod, flow, pkt, len, ts_ms, &info));
}

static router_result router_giveup(struct ndpi_detection_module_struct *mod,
                                   struct ndpi_flow_struct *flow) {
	return router_convert(ndpi_detection_giveup(mod, flow));
}

static char *router_proto_name(struct ndpi_detection_module_struct *mod,
                               u_int16_t master, u_int16_t app, char *buf, u_int len) {
	ndpi_master_app_protocol p;
	p.master_protocol = master;
	p.app_protocol = app;
	return ndpi_protocol2name(mod, p, buf, len);
}

static char *router_get_proto_name(struct ndpi_detection_module_struct *mod, u_int16_t id) {
	return ndpi_get_proto_name(mod, id);
}

static u_int16_t router_get_proto_by_name(struct ndpi_detection_module_struct *mod, const char *name) {
	return ndpi_get_proto_by_name(mod, name);
}

static router_result router_lookup_protocol(struct ndpi_detection_module_struct *mod, const char *name) {
	ndpi_master_app_protocol p = ndpi_get_protocol_by_name(mod, name);
	router_result r;
	r.master = p.master_protocol;
	r.app = p.app_protocol;
	r.category = 0;
	r.state = 0;
	return r;
}

static int router_category_id(struct ndpi_detection_module_struct *mod, const char *name) {
	return ndpi_get_category_id(mod, (char *)name);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unsafe"
)

// State mirrors ndpi_classification_state.
type State uint8

const (
	StateInspecting State = C.NDPI_STATE_INSPECTING
	StatePartial    State = C.NDPI_STATE_PARTIAL
	StateMonitoring State = C.NDPI_STATE_MONITORING
	StateClassified State = C.NDPI_STATE_CLASSIFIED
)

func (s State) String() string {
	switch s {
	case StateInspecting:
		return "inspecting"
	case StatePartial:
		return "partial"
	case StateMonitoring:
		return "monitoring"
	case StateClassified:
		return "classified"
	}
	return fmt.Sprintf("state(%d)", uint8(s))
}

// Final reports whether nDPI will not change the classification any more.
func (s State) Final() bool {
	return s == StateClassified || s == StateMonitoring
}

// Result is the subset of ndpi_protocol needed by the router.
type Result struct {
	Master   uint16
	App      uint16
	Category uint16
	State    State
}

// Known reports whether nDPI identified any protocol.
func (r Result) Known() bool {
	return r.Master != C.NDPI_PROTOCOL_UNKNOWN || r.App != C.NDPI_PROTOCOL_UNKNOWN
}

func newResult(r C.router_result) Result {
	return Result{
		Master:   uint16(r.master),
		App:      uint16(r.app),
		Category: uint16(r.category),
		State:    State(r.state),
	}
}

// MaxPacketLen is the largest L3 packet nDPI accepts (unsigned short).
const MaxPacketLen = 0xffff

var ErrClosed = errors.New("dpi: engine closed")

// Engine owns an nDPI detection module.
type Engine struct {
	mod *C.struct_ndpi_detection_module_struct
}

// New initialises an nDPI detection module with all protocols enabled.
func New() (*Engine, error) {
	mod := C.ndpi_init_detection_module(nil, C.NDPI_LICENSE_NOT_FOR_PROFIT_LGPL)
	if mod == nil {
		return nil, errors.New("dpi: ndpi_init_detection_module failed")
	}
	if rc := C.ndpi_finalize_initialization(mod); rc != 0 {
		C.ndpi_exit_detection_module(mod)
		return nil, fmt.Errorf("dpi: ndpi_finalize_initialization failed: %d", int(rc))
	}
	return &Engine{mod: mod}, nil
}

// Close releases the detection module. All FlowStates must be freed first.
func (e *Engine) Close() {
	if e.mod != nil {
		C.ndpi_exit_detection_module(e.mod)
		e.mod = nil
	}
}

// FlowState is the per-flow nDPI state, allocated in C memory.
type FlowState struct {
	p *C.struct_ndpi_flow_struct
}

// NewFlow allocates a zeroed ndpi_flow_struct.
func (e *Engine) NewFlow() (*FlowState, error) {
	if e.mod == nil {
		return nil, ErrClosed
	}
	p := C.router_flow_alloc()
	if p == nil {
		return nil, errors.New("dpi: ndpi_flow_malloc failed")
	}
	return &FlowState{p: p}, nil
}

// Free releases the C memory of the flow. It is safe to call more than once.
func (fs *FlowState) Free() {
	if fs != nil && fs.p != nil {
		C.ndpi_free_flow(fs.p)
		fs.p = nil
	}
}

// Process feeds one packet, starting at the IP header, to nDPI.
// Packets longer than MaxPacketLen are truncated.
func (e *Engine) Process(fs *FlowState, l3 []byte, tsMs uint64) Result {
	if e.mod == nil || fs == nil || fs.p == nil || len(l3) == 0 {
		return Result{}
	}
	n := len(l3)
	if n > MaxPacketLen {
		n = MaxPacketLen
	}
	r := C.router_process(e.mod, fs.p, (*C.uchar)(unsafe.Pointer(&l3[0])), C.ushort(n), C.u_int64_t(tsMs))
	return newResult(r)
}

// GiveUp asks nDPI for its best guess for a flow whose inspection is over.
func (e *Engine) GiveUp(fs *FlowState) Result {
	if e.mod == nil || fs == nil || fs.p == nil {
		return Result{}
	}
	return newResult(C.router_giveup(e.mod, fs.p))
}

// ProtocolName returns names such as "DNS", "TLS.Google" or "Unknown".
func (e *Engine) ProtocolName(r Result) string {
	if e.mod == nil {
		return ""
	}
	var buf [64]C.char
	p := C.router_proto_name(e.mod, C.u_int16_t(r.Master), C.u_int16_t(r.App), &buf[0], C.u_int(len(buf)))
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// CategoryName returns the nDPI category name, e.g. "Web" or "Network".
func (e *Engine) CategoryName(r Result) string {
	if e.mod == nil {
		return ""
	}
	p := C.ndpi_category_get_name(e.mod, C.ndpi_protocol_category_t(r.Category))
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// Revision returns the nDPI git revision string.
func Revision() string {
	return C.GoString(C.ndpi_revision())
}

// APIVersion returns the nDPI API version number.
func APIVersion() uint16 {
	return uint16(C.ndpi_get_api_version())
}

// ProtoName returns the nDPI name for a single protocol id (master or app).
func (e *Engine) ProtoName(id uint16) string {
	if e.mod == nil || id == C.NDPI_PROTOCOL_UNKNOWN {
		return ""
	}
	p := C.router_get_proto_name(e.mod, C.u_int16_t(id))
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// ProtoByName resolves a master or app protocol name to its id.
func (e *Engine) ProtoByName(name string) (uint16, bool) {
	if e.mod == nil || name == "" {
		return 0, false
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	id := C.router_get_proto_by_name(e.mod, cname)
	if id == C.NDPI_PROTOCOL_UNKNOWN {
		return 0, false
	}
	return uint16(id), true
}

// LookupProtocol resolves a combined name such as "TLS.YouTube".
func (e *Engine) LookupProtocol(name string) (Result, bool) {
	if e.mod == nil || name == "" {
		return Result{}, false
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	r := C.router_lookup_protocol(e.mod, cname)
	res := newResult(r)
	if res.Master == C.NDPI_PROTOCOL_UNKNOWN && res.App == C.NDPI_PROTOCOL_UNKNOWN {
		return Result{}, false
	}
	return res, true
}

// CategoryID resolves a category name to its nDPI id, or false if unknown.
func (e *Engine) CategoryID(name string) (uint16, bool) {
	if e.mod == nil || name == "" {
		return 0, false
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	id := C.router_category_id(e.mod, cname)
	if id < 0 {
		return 0, false
	}
	return uint16(id), true
}

// Categories returns sorted unique category names known to nDPI.
func (e *Engine) Categories() []string {
	if e.mod == nil {
		return nil
	}
	seen := make(map[string]struct{})
	n := int(C.NDPI_PROTOCOL_NUM_CATEGORIES)
	for i := 0; i < n; i++ {
		p := C.ndpi_category_get_name(e.mod, C.ndpi_protocol_category_t(i))
		if p == nil {
			continue
		}
		name := strings.TrimSpace(C.GoString(p))
		if name != "" {
			seen[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
