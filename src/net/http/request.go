// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP Request reading and parsing.

package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/idna"
	"io"
	"mime"
	"mime/multipart"
	"net/http/httptrace"
	"net/http/internal/ascii"
	"net/textproto"
	"net/url"
	urlpkg "net/url"
	"strconv"
	"strings"
	"sync"
	_ "unsafe" // for linkname
)

const (
	defaultMaxMemory = 32 << 20 // 32 MB
)

// ErrMissingFile is returned by FormFile when the provided file field name
// is either not present in the request or not a file field.
var ErrMissingFile = errors.New("http: no such file")

// ProtocolError represents an HTTP protocol error.
//
// Deprecated: Not all errors in the http package related to protocol errors
// are of type ProtocolError.
type ProtocolError struct {
	ErrorString string
}

func (pe *ProtocolError) Error() string { return pe.ErrorString }

// Is lets http.ErrNotSupported match errors.ErrUnsupported.
func (pe *ProtocolError) Is(err error) bool {
	return pe == ErrNotSupported && err == errors.ErrUnsupported
}

var (
	// ErrNotSupported indicates that a feature is not supported.
	//
	// It is returned by ResponseController methods to indicate that
	// the handler does not support the method, and by the Push method
	// of Pusher implementations to indicate that HTTP/2 Push support
	// is not available.
	ErrNotSupported = &ProtocolError{"feature not supported"}

	// Deprecated: ErrUnexpectedTrailer is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrUnexpectedTrailer = &ProtocolError{"trailer header without chunked transfer encoding"}

	// ErrMissingBoundary is returned by Request.MultipartReader when the
	// request's Content-Type does not include a "boundary" parameter.
	ErrMissingBoundary = &ProtocolError{"no multipart boundary param in Content-Type"}

	// ErrNotMultipart is returned by Request.MultipartReader when the
	// request's Content-Type is not multipart/form-data.
	ErrNotMultipart = &ProtocolError{"request Content-Type isn't multipart/form-data"}

	// Deprecated: ErrHeaderTooLong is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrHeaderTooLong = &ProtocolError{"header too long"}

	// Deprecated: ErrShortBody is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrShortBody = &ProtocolError{"entity body too short"}

	// Deprecated: ErrMissingContentLength is no longer returned by
	// anything in the net/http package. Callers should not
	// compare errors against this variable.
	ErrMissingContentLength = &ProtocolError{"missing ContentLength in HEAD response"}
)

func badStringError(what, val string) error { return fmt.Errorf("%s %q", what, val) }

// Headers that Request.Write handles itself and should be skipped.
var reqWriteExcludeHeader = map[string]bool{
	"Host":              true, // not in Header map anyway
	"User-Agent":        true,
	"Content-Length":    true,
	"Transfer-Encoding": true,
	"Trailer":           true,
}

// Request 表示服务器接收的或客户端发送的 HTTP 请求。客户端和服务器使用情况之间的字段语义略有不同。除了有关以下字段的注释外，请参阅 [Request.Write] 和 [RoundTripper] 的文档。
type Request struct {
	// Method 指定 HTTP 方法（GET、POST、PUT 等）。对于客户端请求，空字符串表示 GET。
	Method string

	// URL 指定要请求的 URI（用于服务器请求）或要访问的 URL（用于客户端请求）。
	// 对于服务器请求，URL 是从 Request-Line 上提供的 URI 中解析的，该 URI 存储在 RequestURI 中。
	// 对于大多数请求，除 Path 和 RawQuery 之外的字段将为空。
	// （请参阅 RFC 7230 的第 5.3 节）对于客户端请求，URL 的 Host 指定要连接到的服务器，而 Request's Host 字段可以选择指定要在 HTTP 请求中发送的 Host 标头值。
	URL *url.URL

	// 传入服务器请求的协议版本。对于客户端请求，这些字段将被忽略。
	// HTTP 客户端代码始终使用 HTTP1.1 或 HTTP2。有关详细信息，请参阅有关传输的文档。
	Proto      string // "HTTP/1.0"
	ProtoMajor int    // 1
	ProtoMinor int    // 0

	// Header 包含服务器接收或客户端发送的请求头字段。
	// 如果服务器收到带有标题行的请求，
	//
	//	Host: example.com
	//	accept-encoding: gzip, deflate
	//	Accept-Language: en-us
	//	fOO: Bar
	//	foo: two
	//
	// then
	//
	//	Header = map[string][]string{
	//		"Accept-Encoding": {"gzip, deflate"},
	//		"Accept-Language": {"en-us"},
	//		"Foo": {"Bar", "two"},
	//	}
	//
	// 对于传入的请求，Host 标头将提升为 Request.Host 字段，并从 Header 映射中删除。
	// HTTP 定义标头名称不区分大小写。请求分析器通过使用 CanonicalHeaderKey 来实现此目的，使第一个字符和任何字符后面的连字符为大写，其余字符为小写。
	// 对于客户端请求，某些标头（如 Content-Length 和 Connection）会在需要时自动写入，并且 Header 中的值可能会被忽略。
	// 请参阅 Request.Write 方法的文档。
	Header Header

	// Body 是请求体，对于客户端的请求，nil body 意味着没有请求体，例如 get 请求。
	// http 客户端 Transport 负责调用 Body 的 close 方法。
	// 对于服务端请求，请求体始终为非 nil，但在不存在正文时将立即返回 EOF。
	// 服务端将关闭请求体。ServeHTTP 处理程序不需要关闭。
	// 正文必须允许 Read 与 Close 同时调用。具体而言，调用 Close 应取消阻塞正在等待输入的 Read。
	Body io.ReadCloser

	// GetBody 定义了一个可选的 func 来返回 Body 的新副本。
	// 它用于当重定向需要多次读取 body 时的客户端请求。
	// 使用 GetBody 仍需要设置 Body。对于服务器请求，它是未使用的。
	GetBody func() (io.ReadCloser, error)

	// ContentLength 记录关联内容的长度。值 -1 表示长度未知。值 >= 0 表示可以从 Body 读取给定的字节数。
	// 对于客户端请求，值为 0 且非 nil Body 也被视为未知。
	ContentLength int64

	// TransferEncoding 列出了从最外层到最内层的传输编码。空列表表示“标识”编码。
	// TransferEncoding 通常可以忽略;在发送和接收请求时，会根据需要自动添加和删除分块编码。
	TransferEncoding []string

	// Close 指示是在回复此请求（对于服务器）后关闭连接，还是在发送此请求并读取其响应（对于客户端）后关闭连接。
	// 对于服务器请求，HTTP 服务器会自动处理此字段，并且处理程序不需要此字段。
	// 对于客户端请求，设置此字段可防止在对相同主机的请求之间重复使用 TCP 连接，就像设置了 Transport.DisableKeepAlives 一样。
	Close bool

	// 对于服务器请求，Host 指定在其上查找 URL 的 Host。
	// 对于 HTTP1（根据 RFC 7230 第 5.4 节），这是“Host”标头的值或 URL 本身中给出的 Host 名。
	// 对于 HTTP2，它是 “：authority” 伪标头字段的值。它可能采用“host：port”的形式。
	// 对于国际域名，Host 可以是 Punycode 或 Unicode 格式。 如果需要，请使用 golang.orgxnetidna 将其转换为任一格式。
	// 为了防止 DNS 重新绑定攻击，服务器处理程序应验证 Host 标头是否具有处理程序认为自己具有权威性的值。
	// 附带的 ServeMux 支持注册到特定主机名的模式，从而保护其已注册的处理程序。
	// 对于客户端请求，Host 可以选择性地覆盖要发送的 Host 标头。
	// 如果为空，则 Request.Write 方法使用 URL.Host 的值。Host 可能包含国际域名。
	Host string

	// Form 包含解析的表单数据，包括URL字段的查询参数和PATCH、POST或PUT表单数据。
	// 此字段仅在调用 ParseForm 后可用。HTTP 客户端忽略 Form 并改用 Body。
	Form url.Values

	// PostForm 包含来自 PATCH、POST 或 PUT body 参数的解析表单数据。
	// 此字段仅在调用 ParseForm 后可用。HTTP 客户端忽略 PostForm 并改用 Body。
	PostForm url.Values

	// MultipartForm 是解析的多部分表单，包括文件上传。
	// 此字段仅在调用 ParseMultipartForm 后可用。HTTP 客户端忽略 MultipartForm 并改用 Body。
	MultipartForm *multipart.Form

	// Trailer 指定在请求体之后发送的其他标头。对于服务器请求，Trailer 映射最初仅包含 Trailer 键，值为 nil（客户声明稍后将发送哪些 trailers）。
	// 当处理程序从 Body 读取时，它不能引用 Trailer。从 Body 读到返回的 EOF 后，可以再次读取 Trailer，并且如果它们是由客户端发送的，则将包含非 nil 值。
	// 对于客户端请求，必须将 Trailer 初始化为包含稍后发送的 Trailer 键的映射。这些值可能是 nil 或其最终值。
	// ContentLength 必须为 0 或 -1，才能发送分块请求。发送 HTTP 请求后，可以在读取请求体时更新映射值。
	// 一旦正文返回 EOF，调用方不得改变 Trailer。很少有 HTTP 客户端、服务器或代理支持 HTTP 尾部。
	Trailer Header

	// RemoteAddr允许HTTP服务器和其他软件记录发送请求的网络地址，通常用于日志记录。此字段未由 ReadRequest 填充，并且没有定义的格式。
	// 此包中的 HTTP 服务器在调用处理程序之前将 RemoteAddr 设置为“IP：port”地址。HTTP 客户端将忽略此字段。
	RemoteAddr string

	// RequestURI 是客户端发送到服务器的 Request-Line（RFC 7230，第 3.1.1 节）的未修改请求目标。
	// 通常，应改用 URL 字段。在 HTTP 客户端请求中设置此字段是错误的。
	RequestURI string

	// TLS 允许 HTTP 服务器和其他软件记录有关接收请求的 TLS 连接的信息。ReadRequest 不填充此字段。
	// 此包中的 HTTP 服务器在调用处理程序之前为启用 TLS 的连接设置字段;否则，它将使字段为零。HTTP 客户端将忽略此字段。
	TLS *tls.ConnectionState

	// Cancel 是一个可选通道，其关闭表示客户端请求应被视为已取消。并非所有 RoundTripper 实现都支持 Cancel。对于服务器请求，此字段不适用。
	// Deprecated：改用 NewRequestWithContext 设置请求的上下文。如果 Request 的 Cancel 字段和上下文都已设置，则不确定是否遵循 Cancel。
	Cancel <-chan struct{}

	// Response 是导致创建此请求的重定向响应。此字段仅在客户端重定向期间填充。
	Response *Response

	// Pattern 是与请求匹配的 [ServeMux] 模式。如果请求未与模式匹配，则为空。
	Pattern string

	// ctx 是客户端上下文或服务器上下文。它只能通过使用 Clone 或 WithContext 复制整个请求来修改。
	// 它是未导出的，以防止人们错误地使用 Context 并改变同一请求的调用者持有的上下文。
	ctx context.Context

	// The following fields are for requests matched by ServeMux.
	// 以下字段用于 ServeMux 匹配的请求。
	pat         *pattern          // 匹配的模式
	matches     []string          // pat 中匹配通配符的值
	otherValues map[string]string // 对于与通配符不匹配的对 SetPathValue 的调用
}

// Context 返回请求的上下文。若要更改上下文，请使用 [Request.Clone] 或 [Request.WithContext]。
// 返回的上下文始终是非 nil，它默认为 background context。
// 对于传出的客户端请求，上下文控制取消。对于传入的服务器请求，当客户端的连接关闭、请求被取消（使用 HTTP2）或 ServeHTTP 方法返回时，上下文将被取消。
func (r *Request) Context() context.Context {
	if r.ctx != nil {
		return r.ctx
	}
	return context.Background()
}

// WithContext 返回 r 的浅拷贝，其上下文更改为 ctx。提供的 ctx 必须为非 nil。
// 对于传出的客户端请求，上下文控制请求及其响应的整个生命周期：获取连接、发送请求以及读取响应标头和正文。
// 若要创建具有上下文的新请求，请使用 [NewRequestWithContext]。要使用新上下文深层复制请求，请使用 [Request.Clone]。
func (r *Request) WithContext(ctx context.Context) *Request {
	if ctx == nil {
		panic("nil context")
	}
	r2 := new(Request)
	*r2 = *r
	r2.ctx = ctx
	return r2
}

// Clone 返回 r 的深度副本，其上下文更改为 ctx。提供的 ctx 必须为非 nil。Clone 仅创建 Body 字段的浅层副本。
// 对于传出的客户端请求，上下文控制请求及其响应的整个生命周期：获取连接、发送请求以及读取响应标头和正文。
func (r *Request) Clone(ctx context.Context) *Request {
	if ctx == nil {
		panic("nil context")
	}
	r2 := new(Request)
	*r2 = *r
	r2.ctx = ctx
	r2.URL = cloneURL(r.URL)
	if r.Header != nil {
		r2.Header = r.Header.Clone()
	}
	if r.Trailer != nil {
		r2.Trailer = r.Trailer.Clone()
	}
	if s := r.TransferEncoding; s != nil {
		s2 := make([]string, len(s))
		copy(s2, s)
		r2.TransferEncoding = s2
	}
	r2.Form = cloneURLValues(r.Form)
	r2.PostForm = cloneURLValues(r.PostForm)
	r2.MultipartForm = cloneMultipartForm(r.MultipartForm)

	// Copy matches and otherValues. See issue 61410.
	if s := r.matches; s != nil {
		s2 := make([]string, len(s))
		copy(s2, s)
		r2.matches = s2
	}
	if s := r.otherValues; s != nil {
		s2 := make(map[string]string, len(s))
		for k, v := range s {
			s2[k] = v
		}
		r2.otherValues = s2
	}
	return r2
}

// ProtoAtLeast 报告请求中使用的 HTTP 协议是否至少为 major.minor
func (r *Request) ProtoAtLeast(major, minor int) bool {
	return r.ProtoMajor > major ||
		r.ProtoMajor == major && r.ProtoMinor >= minor
}

// UserAgent 返回客户端的 User-Agent，如果在请求中发送了。
func (r *Request) UserAgent() string {
	return r.Header.Get("User-Agent")
}

// Cookies 解析并返回与请求一起发送的 HTTP Cookie
func (r *Request) Cookies() []*Cookie {
	return readCookies(r.Header, "")
}

// CookiesNamed 分析并返回与请求一起发送的命名 HTTP Cookie，如果没有匹配，则返回一个空切片。
func (r *Request) CookiesNamed(name string) []*Cookie {
	if name == "" {
		return []*Cookie{}
	}
	return readCookies(r.Header, name)
}

// ErrNoCookie 当未找到 Cookie 时，Request的 Cookie 方法将返回 ErrNoCookie。
var ErrNoCookie = errors.New("http: named cookie not present")

// Cookie 返回请求中提供的命名 Cookie，如果未找到，则返回 [ErrNoCookie]。如果多个 cookie 与给定名称匹配，则仅返回一个 cookie。
func (r *Request) Cookie(name string) (*Cookie, error) {
	if name == "" {
		return nil, ErrNoCookie
	}
	for _, c := range readCookies(r.Header, name) {
		return c, nil
	}
	return nil, ErrNoCookie
}

// AddCookie 将 Cookie 添加到请求中。根据 RFC 6265 第 5.4 节，AddCookie 不会附加多个 [Cookie] 标头字段。
// 这意味着所有 cookie（如果有的话）都写在同一行中，用分号分隔。
// AddCookie 仅清理 c 的名称和值，而不清理请求中已存在的 Cookie 标头。
func (r *Request) AddCookie(c *Cookie) {
	s := fmt.Sprintf("%s=%s", sanitizeCookieName(c.Name), sanitizeCookieValue(c.Value, c.Quoted))
	if c := r.Header.Get("Cookie"); c != "" {
		r.Header.Set("Cookie", c+"; "+s)
	} else {
		r.Header.Set("Cookie", s)
	}
}

// Referer 如果在请求中发送，Referer 将返回引用 URL。Referer 的拼写错误与请求本身一样，这是 HTTP 早期的错误。
// 也可以从 [Header] 映射中获取此值作为 Header[“Referer”];将其作为一种方法提供的好处是，
// 编译器可以诊断使用备用（正确的英语）拼写 req.Referrer() 的程序，但无法诊断使用 Header[“Referrer”] 的程序。
func (r *Request) Referer() string {
	return r.Header.Get("Referer")
}

// multipartByReader 是一个哨兵值。它在 Request.MultipartForm 中的存在表明已将请求正文的分析移交给 MultipartReader 而不是 ParseMultipartForm。
var multipartByReader = &multipart.Form{
	Value: make(map[string][]string),
	File:  make(map[string][]*multipart.FileHeader),
}

// MultipartReader 如果这是 multipartform-data 或 multipartmixed POST 请求，
// 则 MultipartReader 返回 MIME multipart 读取器，否则返回 nil 和错误。
// 使用此函数而不是 [Request.ParseMultipartForm] 将请求正文处理为流。
func (r *Request) MultipartReader() (*multipart.Reader, error) {
	if r.MultipartForm == multipartByReader {
		return nil, errors.New("http: MultipartReader called twice")
	}
	if r.MultipartForm != nil {
		return nil, errors.New("http: multipart handled by ParseMultipartForm")
	}
	r.MultipartForm = multipartByReader
	return r.multipartReader(true)
}

func (r *Request) multipartReader(allowMixed bool) (*multipart.Reader, error) {
	v := r.Header.Get("Content-Type")
	if v == "" {
		return nil, ErrNotMultipart
	}
	if r.Body == nil {
		return nil, errors.New("missing form body")
	}
	d, params, err := mime.ParseMediaType(v)
	if err != nil || !(d == "multipart/form-data" || allowMixed && d == "multipart/mixed") {
		return nil, ErrNotMultipart
	}
	boundary, ok := params["boundary"]
	if !ok {
		return nil, ErrMissingBoundary
	}
	return multipart.NewReader(r.Body, boundary), nil
}

// isH2Upgrade reports whether r represents the http2 "client preface"
// magic string.
func (r *Request) isH2Upgrade() bool {
	return r.Method == "PRI" && len(r.Header) == 0 && r.URL.Path == "*" && r.Proto == "HTTP/2.0"
}

// 如果 value 非空则返回 value，否则返回 def
func valueOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}

// 这并不是为了反映正在使用的实际 Go 版本。它在 Go 1.1 发布时进行了更改，因为以前的 User-Agent 最终被一些入侵检测系统阻止了。
// See https://codereview.appspot.com/7532043.
const defaultUserAgent = "Go-http-client/1.1"

// Write 以连线格式写入 HTTP1.1 请求，即标头和正文。此方法查询请求的以下字段：
//
//	Host
//	URL
//	Method (defaults to "GET")
//	Header
//	ContentLength
//	TransferEncoding
//	Body
//
// 如果存在 Body，则 Content-Length 为 <= 0，并且 [Request.TransferEncoding] 未设置为 “identity”，
// 则 Write 会将“Transfer-Encoding： chunked”添加到标头。Body 在发送后关闭。
func (r *Request) Write(w io.Writer) error {
	return r.write(w, false, nil, nil)
}

// WriteProxy 类似于 [Request.Write]，但以 HTTP 代理预期的格式编写请求。
// 具体而言，[Request.WriteProxy] 根据 RFC 7230 的第 5.3 节，使用绝对 URI 写入请求的初始 Request-URI 行，包括协议和host。
// 无论哪种情况，WriteProxy 都会使用 r.Host 或 r.URL.Host 写 Host 头部。
func (r *Request) WriteProxy(w io.Writer) error {
	return r.write(w, true, nil, nil)
}

// errMissingHost 当请求中不存在 Host 或 URL 时，Write 将返回 errMissingHost。
var errMissingHost = errors.New("http: Request.Write on Request with no Host or URL set")

// extraHeaders may be nil
// waitForContinue may be nil
// always closes body
func (r *Request) write(w io.Writer, usingProxy bool, extraHeaders Header, waitForContinue func() bool) (err error) {
	trace := httptrace.ContextClientTrace(r.Context())
	if trace != nil && trace.WroteRequest != nil {
		defer func() {
			trace.WroteRequest(httptrace.WroteRequestInfo{
				Err: err,
			})
		}()
	}
	closed := false
	defer func() {
		if closed {
			return
		}
		if closeErr := r.closeBody(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	// 查找目标主机。首选 Host: header，但如果没有给出，请使用请求 URL 中的主机。
	// 清理 host，以防它带着意想不到的东西到达。
	host := r.Host
	if host == "" {
		if r.URL == nil {
			return errMissingHost
		}
		host = r.URL.Host
	}
	host, err = httpguts.PunycodeHostPort(host)
	if err != nil {
		return err
	}
	// Validate that the Host header is a valid header in general,
	// but don't validate the host itself. This is sufficient to avoid
	// header or request smuggling via the Host field.
	// The server can (and will, if it's a net/http server) reject
	// the request if it doesn't consider the host valid.
	// 验证 Host 标头通常是否为有效标头，但不要验证 host 本身。这足以避免通过标头或请求走私 Host 字段。
	// 如果服务器认为主机无效，它可以（并且如果它是 nethttp 服务器）拒绝该请求。
	if !httpguts.ValidHostHeader(host) {
		// 从历史上看，我们会在 '/' 或 ' ' 之后截断 Host 标头。
		// 一些用户依赖此截断将网络地址（如 Unix 域套接字路径）转换为有效的、被忽略的 Host 标头（请参阅 https：go.devissue61431）。
		// 我们不会保留截断，因为发送更改的标头字段会打开走私向量。相反，如果 Host 标头无效，则将其完全清零。
		// 空主机有效;请参阅 RFC 9112 第 3.2 节。如果我们发送到代理，则返回错误，因为代理可能无法使用空的 Host 标头执行任何有用的操作。
		if !usingProxy {
			host = ""
		} else {
			return errors.New("http: invalid Host header")
		}
	}

	// According to RFC 6874, an HTTP client, proxy, or other
	// intermediary must remove any IPv6 zone identifier attached
	// to an outgoing URI.
	host = removeZone(host)

	ruri := r.URL.RequestURI()
	if usingProxy && r.URL.Scheme != "" && r.URL.Opaque == "" {
		ruri = r.URL.Scheme + "://" + host + ruri
	} else if r.Method == "CONNECT" && r.URL.Path == "" {
		// CONNECT requests normally give just the host and port, not a full URL.
		ruri = host
		if r.URL.Opaque != "" {
			ruri = r.URL.Opaque
		}
	}
	if stringContainsCTLByte(ruri) {
		return errors.New("net/http: can't write control character in Request.URL")
	}
	// TODO: validate r.Method too? At least it's less likely to
	// come from an attacker (more likely to be a constant in
	// code).

	// Wrap the writer in a bufio Writer if it's not already buffered.
	// Don't always call NewWriter, as that forces a bytes.Buffer
	// and other small bufio Writers to have a minimum 4k buffer
	// size.
	var bw *bufio.Writer
	if _, ok := w.(io.ByteWriter); !ok {
		bw = bufio.NewWriter(w)
		w = bw
	}

	_, err = fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", valueOrDefault(r.Method, "GET"), ruri)
	if err != nil {
		return err
	}

	// Header lines
	_, err = fmt.Fprintf(w, "Host: %s\r\n", host)
	if err != nil {
		return err
	}
	if trace != nil && trace.WroteHeaderField != nil {
		trace.WroteHeaderField("Host", []string{host})
	}

	// Use the defaultUserAgent unless the Header contains one, which
	// may be blank to not send the header.
	userAgent := defaultUserAgent
	if r.Header.has("User-Agent") {
		userAgent = r.Header.Get("User-Agent")
	}
	if userAgent != "" {
		userAgent = headerNewlineToSpace.Replace(userAgent)
		userAgent = textproto.TrimString(userAgent)
		_, err = fmt.Fprintf(w, "User-Agent: %s\r\n", userAgent)
		if err != nil {
			return err
		}
		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField("User-Agent", []string{userAgent})
		}
	}

	// Process Body,ContentLength,Close,Trailer
	tw, err := newTransferWriter(r)
	if err != nil {
		return err
	}
	err = tw.writeHeader(w, trace)
	if err != nil {
		return err
	}

	err = r.Header.writeSubset(w, reqWriteExcludeHeader, trace)
	if err != nil {
		return err
	}

	if extraHeaders != nil {
		err = extraHeaders.write(w, trace)
		if err != nil {
			return err
		}
	}

	_, err = io.WriteString(w, "\r\n")
	if err != nil {
		return err
	}

	if trace != nil && trace.WroteHeaders != nil {
		trace.WroteHeaders()
	}

	// Flush and wait for 100-continue if expected.
	if waitForContinue != nil {
		if bw, ok := w.(*bufio.Writer); ok {
			err = bw.Flush()
			if err != nil {
				return err
			}
		}
		if trace != nil && trace.Wait100Continue != nil {
			trace.Wait100Continue()
		}
		if !waitForContinue() {
			closed = true
			r.closeBody()
			return nil
		}
	}

	if bw, ok := w.(*bufio.Writer); ok && tw.FlushHeaders {
		if err := bw.Flush(); err != nil {
			return err
		}
	}

	// Write body and trailer
	closed = true
	err = tw.writeBody(w)
	if err != nil {
		if tw.bodyReadError == err {
			err = requestBodyReadError{err}
		}
		return err
	}

	if bw != nil {
		return bw.Flush()
	}
	return nil
}

// requestBodyReadError 包装来自 (*Request).write 的错误，以指示错误来自 Request.Body 上的 Read 调用。
// 此错误类型不应将 net/http 包转义给用户。
type requestBodyReadError struct{ error }

func idnaASCII(v string) (string, error) {
	// TODO：在验证性能正常后，请考虑删除此检查。现在，punycode 验证、长度检查、上下文检查和允许的字符测试都被省略了。
	// 如果可能，它还可以防止 ToASCII 调用挽救无效的 IDN。因此，可能会有两个 IDN 对用户看起来完全相同，
	// 其中仅 ASCII 版本会导致下游错误，而非 ASCII 版本则不会。请注意，对于正确的 ASCII IDN，ToASCII 只会做更多的工作，但不会导致分配。
	if ascii.Is(v) {
		return v, nil
	}
	return idna.Lookup.ToASCII(v)
}

// removeZone 从 host 中删除 IPv6 区域标识符。例如，“[fe80::1%en0]:8080”更改为“[fe80::1]:8080”
func removeZone(host string) string {
	if !strings.HasPrefix(host, "[") {
		return host
	}
	i := strings.LastIndex(host, "]")
	if i < 0 {
		return host
	}
	j := strings.LastIndex(host[:i], "%")
	if j < 0 {
		return host
	}
	return host[:j] + host[i:]
}

// ParseHTTPVersion 根据 RFC 7230 的第 2.6 节分析 HTTP 版本字符串。
// “HTTP1.0” 返回 （1， 0， true）。请注意，没有次要版本的字符串（例如“HTTP2”）是无效的。
func ParseHTTPVersion(vers string) (major, minor int, ok bool) {
	switch vers {
	case "HTTP/1.1":
		return 1, 1, true
	case "HTTP/1.0":
		return 1, 0, true
	}
	if !strings.HasPrefix(vers, "HTTP/") {
		return 0, 0, false
	}
	if len(vers) != len("HTTP/X.Y") {
		return 0, 0, false
	}
	if vers[6] != '.' {
		return 0, 0, false
	}
	maj, err := strconv.ParseUint(vers[5:6], 10, 0)
	if err != nil {
		return 0, 0, false
	}
	min, err := strconv.ParseUint(vers[7:8], 10, 0)
	if err != nil {
		return 0, 0, false
	}
	return int(maj), int(min), true
}

// 请求方法是否有效
func validMethod(method string) bool {
	/*
	     Method         = "OPTIONS"                ; Section 9.2
	                    | "GET"                    ; Section 9.3
	                    | "HEAD"                   ; Section 9.4
	                    | "POST"                   ; Section 9.5
	                    | "PUT"                    ; Section 9.6
	                    | "DELETE"                 ; Section 9.7
	                    | "TRACE"                  ; Section 9.8
	                    | "CONNECT"                ; Section 9.9
	                    | extension-method
	   extension-method = token
	     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

// NewRequest 使用 [context.Background] 包装 [NewRequestWithContext].
func NewRequest(method, url string, body io.Reader) (*Request, error) {
	return NewRequestWithContext(context.Background(), method, url, body)
}

// NewRequestWithContext 通过给定方法、URL 和可选的body 返回一个新的 [Request]，如果没有特别指定，默认http1.1，get方法。
// 如果提供的 body 也是 [io.Closer]，返回的 [Request.Body] 设置为 body，
// 并将由 Client 方法 Do、Post 和 PostForm 以及 [Transport.RoundTrip] 关闭（可能是异步的）。
//
// NewRequestWithContext 返回适合与 [Client.Do] 或 [Transport.RoundTrip] 一起使用的请求。
// 若要创建用于测试服务器处理程序的请求，请使用 nethttphttptest 包中的 [NewRequest] 函数，使用 [ReadRequest]，或手动更新请求字段。
// 对于传出的客户端请求，上下文控制请求及其响应的整个生命周期：包含获取连接、发送请求以及读取响应标头和正文。
// 请参阅请求类型的文档，了解入站和出站请求字段之间的区别。
//
// 如果 body 的类型为 [*bytes.Buffer], [*bytes.Reader], or [*strings.Reader]，
// 返回的请求的 ContentLength 设置为其确切值（而不是 -1），填充 GetBody（因此 307 和 308 重定向可以重播正文），
// 如果 ContentLength 为 0，则将 Body 设置为 [NoBody]。
func NewRequestWithContext(ctx context.Context, method, url string, body io.Reader) (*Request, error) {
	if method == "" {
		// 我们记录了 “” 表示 Request.Method 的 “GET”，人们依赖于 NewRequest 的它，因此请保持其工作状态。
		// 我们仍然对非空方法强制执行 validMethod。
		method = "GET"
	}
	if !validMethod(method) {
		return nil, fmt.Errorf("net/http: invalid method %q", method)
	}
	if ctx == nil {
		return nil, errors.New("net/http: nil Context")
	}
	u, err := urlpkg.Parse(url)
	if err != nil {
		return nil, err
	}
	rc, ok := body.(io.ReadCloser)
	if !ok && body != nil {
		// 将非空 body 转为 ReadCloser 类型
		rc = io.NopCloser(body)
	}
	// The host's colon:port should be normalized. See Issue 14836.
	u.Host = removeEmptyPort(u.Host)
	req := &Request{
		ctx:        ctx,
		Method:     method,
		URL:        u,
		Proto:      "HTTP/1.1", // 默认版本 1.1
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(Header),
		Body:       rc,
		Host:       u.Host,
	}
	if body != nil {
		// 能够获取 body 的类型时，获取其真实的长度
		switch v := body.(type) {
		case *bytes.Buffer:
			req.ContentLength = int64(v.Len())
			buf := v.Bytes()
			req.GetBody = func() (io.ReadCloser, error) {
				r := bytes.NewReader(buf)
				return io.NopCloser(r), nil
			}
		case *bytes.Reader:
			req.ContentLength = int64(v.Len())
			snapshot := *v
			req.GetBody = func() (io.ReadCloser, error) {
				r := snapshot
				return io.NopCloser(&r), nil
			}
		case *strings.Reader:
			req.ContentLength = int64(v.Len())
			snapshot := *v
			req.GetBody = func() (io.ReadCloser, error) {
				r := snapshot
				return io.NopCloser(&r), nil
			}
		default:
			// This is where we'd set it to -1 (at least
			// if body != NoBody) to mean unknown, but
			// that broke people during the Go 1.8 testing
			// period. People depend on it being 0 I
			// guess. Maybe retry later. See Issue 18117.
		}
		// 对于客户端请求，Request.ContentLength 为 0 表示实际为 0 或未知。
		// 明确指出 ContentLength 为 0 的唯一方法是将 Body 设置为 nil。但事实证明，
		// 太多的代码依赖于 NewRequest 返回非 nil Body，因此我们改用了一个众所周知的 ReadCloser 变量，
		// 并让 http 包也将该 sentinel 变量显式表示为零。
		if req.GetBody != nil && req.ContentLength == 0 {
			req.Body = NoBody
			req.GetBody = func() (io.ReadCloser, error) { return NoBody, nil }
		}
	}

	return req, nil
}

// BasicAuth 如果请求使用 HTTP 基本身份验证，则 BasicAuth 返回请求的 Authorization 标头中提供的用户名和密码。请参阅 RFC 2617 的第 2 节。
func (r *Request) BasicAuth() (username, password string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", false
	}
	return parseBasicAuth(auth)
}

// parseBasicAuth 解析 HTTP 基本身份验证字符串。
// “Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==” 返回 （“Aladdin”， “open sesame”， true）。
// parseBasicAuth 应该是一个内部细节，但广泛使用的包使用 linkname 来访问它。
// 不要删除或更改类型签名。请参阅 go.devissue67401。
//
//go:linkname parseBasicAuth
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !ascii.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}

// SetBasicAuth 将请求的 Authorization 标头设置为使用提供的用户名和密码的 HTTP 基本身份验证。
// 使用 HTTP 基本身份验证时，提供的用户名和密码不会加密。它通常只应在 HTTPS 请求中使用。
// 用户名不能包含冒号。某些协议可能会对预转义用户名和密码施加额外的要求。
// 例如，当与 OAuth2 一起使用时，必须首先使用 [url.QueryEscape]。
func (r *Request) SetBasicAuth(username, password string) {
	r.Header.Set("Authorization", "Basic "+basicAuth(username, password))
}

// parseRequestLine 解析请求行 "GET /foo HTTP/1.1" into its three parts.
func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	method, rest, ok1 := strings.Cut(line, " ")
	requestURI, proto, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 {
		return "", "", "", false
	}
	return method, requestURI, proto, true
}

// 文本协议读取池
var textprotoReaderPool sync.Pool

func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
	if v := textprotoReaderPool.Get(); v != nil {
		tr := v.(*textproto.Reader)
		tr.R = br
		return tr
	}
	return textproto.NewReader(br)
}

func putTextprotoReader(r *textproto.Reader) {
	r.R = nil
	textprotoReaderPool.Put(r)
}

// ReadRequest 读取并分析来自 b 的传入请求。
// ReadRequest 是一个低级函数，只应用于专用应用程序
// 大多数代码应使用 [Server] 来读取请求并通过 [Handler] 接口处理它们。
// ReadRequest 仅支持 HTTP1.x 请求。对于 HTTP2，请使用 golang.orgxnethttp2。
func ReadRequest(b *bufio.Reader) (*Request, error) {
	req, err := readRequest(b)
	if err != nil {
		return nil, err
	}

	delete(req.Header, "Host")
	return req, err
}

// readRequest should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/sagernet/sing
//   - github.com/v2fly/v2ray-core/v4
//   - github.com/v2fly/v2ray-core/v5
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname readRequest
func readRequest(b *bufio.Reader) (req *Request, err error) {
	tp := newTextprotoReader(b)
	defer putTextprotoReader(tp)

	req = new(Request)

	// First line: GET /index.html HTTP/1.0
	var s string
	if s, err = tp.ReadLine(); err != nil {
		return nil, err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	var ok bool
	req.Method, req.RequestURI, req.Proto, ok = parseRequestLine(s)
	if !ok {
		return nil, badStringError("malformed HTTP request", s)
	}
	if !validMethod(req.Method) {
		return nil, badStringError("invalid method", req.Method)
	}
	rawurl := req.RequestURI
	if req.ProtoMajor, req.ProtoMinor, ok = ParseHTTPVersion(req.Proto); !ok {
		return nil, badStringError("malformed HTTP version", req.Proto)
	}

	// CONNECT 请求有两种不同的使用方式，并且都不使用完整的 URL：标准用途是通过 HTTP 代理隧道 HTTPS。
	// 它看起来像“CONNECT www.google.com:443 HTTP1.1”，参数只是 URL 的权限部分。
	// 此信息应包含在 req.URL.Host。net/rpc 包也使用 CONNECT，但其中的参数是以斜杠开头的路径。
	// 它可以使用常规 URL 解析器进行解析，路径将以req.URL.Path 结尾，它需要位于何处才能使 RPC 正常工作。
	justAuthority := req.Method == "CONNECT" && !strings.HasPrefix(rawurl, "/")
	if justAuthority {
		rawurl = "http://" + rawurl
	}

	if req.URL, err = url.ParseRequestURI(rawurl); err != nil {
		return nil, err
	}

	if justAuthority {
		// Strip the bogus "http://" back off.
		req.URL.Scheme = ""
	}

	// Subsequent lines: Key: value.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	req.Header = Header(mimeHeader)
	if len(req.Header["Host"]) > 1 {
		return nil, fmt.Errorf("too many Host headers")
	}

	// RFC 7230, section 5.3: Must treat
	//	GET /index.html HTTP/1.1
	//	Host: www.google.com
	// and
	//	GET http://www.google.com/index.html HTTP/1.1
	//	Host: doesntmatter
	// the same. In the second case, any Host line is ignored.
	req.Host = req.URL.Host
	if req.Host == "" {
		req.Host = req.Header.get("Host")
	}

	fixPragmaCacheControl(req.Header)

	req.Close = shouldClose(req.ProtoMajor, req.ProtoMinor, req.Header, false)

	err = readTransfer(req, b)
	if err != nil {
		return nil, err
	}

	if req.isH2Upgrade() {
		// Because it's neither chunked, nor declared:
		req.ContentLength = -1

		// We want to give handlers a chance to hijack the
		// connection, but we need to prevent the Server from
		// dealing with the connection further if it's not
		// hijacked. Set Close to ensure that:
		req.Close = true
	}
	return req, nil
}

// MaxBytesReader is similar to [io.LimitReader] but is intended for
// limiting the size of incoming request bodies. In contrast to
// io.LimitReader, MaxBytesReader's result is a ReadCloser, returns a
// non-nil error of type [*MaxBytesError] for a Read beyond the limit,
// and closes the underlying reader when its Close method is called.
//
// MaxBytesReader prevents clients from accidentally or maliciously
// sending a large request and wasting server resources. If possible,
// it tells the [ResponseWriter] to close the connection after the limit
// has been reached.
func MaxBytesReader(w ResponseWriter, r io.ReadCloser, n int64) io.ReadCloser {
	if n < 0 { // Treat negative limits as equivalent to 0.
		n = 0
	}
	return &maxBytesReader{w: w, r: r, i: n, n: n}
}

// MaxBytesError is returned by [MaxBytesReader] when its read limit is exceeded.
type MaxBytesError struct {
	Limit int64
}

func (e *MaxBytesError) Error() string {
	// Due to Hyrum's law, this text cannot be changed.
	return "http: request body too large"
}

type maxBytesReader struct {
	w   ResponseWriter
	r   io.ReadCloser // underlying reader
	i   int64         // max bytes initially, for MaxBytesError
	n   int64         // max bytes remaining
	err error         // sticky error
}

func (l *maxBytesReader) Read(p []byte) (n int, err error) {
	if l.err != nil {
		return 0, l.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	// If they asked for a 32KB byte read but only 5 bytes are
	// remaining, no need to read 32KB. 6 bytes will answer the
	// question of the whether we hit the limit or go past it.
	// 0 < len(p) < 2^63
	if int64(len(p))-1 > l.n {
		p = p[:l.n+1]
	}
	n, err = l.r.Read(p)

	if int64(n) <= l.n {
		l.n -= int64(n)
		l.err = err
		return n, err
	}

	n = int(l.n)
	l.n = 0

	// The server code and client code both use
	// maxBytesReader. This "requestTooLarge" check is
	// only used by the server code. To prevent binaries
	// which only using the HTTP Client code (such as
	// cmd/go) from also linking in the HTTP server, don't
	// use a static type assertion to the server
	// "*response" type. Check this interface instead:
	type requestTooLarger interface {
		requestTooLarge()
	}
	if res, ok := l.w.(requestTooLarger); ok {
		res.requestTooLarge()
	}
	l.err = &MaxBytesError{l.i}
	return n, l.err
}

func (l *maxBytesReader) Close() error {
	return l.r.Close()
}

func copyValues(dst, src url.Values) {
	for k, vs := range src {
		dst[k] = append(dst[k], vs...)
	}
}

func parsePostForm(r *Request) (vs url.Values, err error) {
	if r.Body == nil {
		err = errors.New("missing form body")
		return
	}
	ct := r.Header.Get("Content-Type")
	// RFC 7231, section 3.1.1.5 - empty type
	//   MAY be treated as application/octet-stream
	if ct == "" {
		ct = "application/octet-stream"
	}
	ct, _, err = mime.ParseMediaType(ct)
	switch {
	case ct == "application/x-www-form-urlencoded":
		var reader io.Reader = r.Body
		maxFormSize := int64(1<<63 - 1)
		if _, ok := r.Body.(*maxBytesReader); !ok {
			maxFormSize = int64(10 << 20) // 10 MB is a lot of text.
			reader = io.LimitReader(r.Body, maxFormSize+1)
		}
		b, e := io.ReadAll(reader)
		if e != nil {
			if err == nil {
				err = e
			}
			break
		}
		if int64(len(b)) > maxFormSize {
			err = errors.New("http: POST too large")
			return
		}
		vs, e = url.ParseQuery(string(b))
		if err == nil {
			err = e
		}
	case ct == "multipart/form-data":
		// handled by ParseMultipartForm (which is calling us, or should be)
		// TODO(bradfitz): there are too many possible
		// orders to call too many functions here.
		// Clean this up and write more tests.
		// request_test.go contains the start of this,
		// in TestParseMultipartFormOrder and others.
	}
	return
}

// ParseForm populates r.Form and r.PostForm.
//
// For all requests, ParseForm parses the raw query from the URL and updates
// r.Form.
//
// For POST, PUT, and PATCH requests, it also reads the request body, parses it
// as a form and puts the results into both r.PostForm and r.Form. Request body
// parameters take precedence over URL query string values in r.Form.
//
// If the request Body's size has not already been limited by [MaxBytesReader],
// the size is capped at 10MB.
//
// For other HTTP methods, or when the Content-Type is not
// application/x-www-form-urlencoded, the request Body is not read, and
// r.PostForm is initialized to a non-nil, empty value.
//
// [Request.ParseMultipartForm] calls ParseForm automatically.
// ParseForm is idempotent.
func (r *Request) ParseForm() error {
	var err error
	if r.PostForm == nil {
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			r.PostForm, err = parsePostForm(r)
		}
		if r.PostForm == nil {
			r.PostForm = make(url.Values)
		}
	}
	if r.Form == nil {
		if len(r.PostForm) > 0 {
			r.Form = make(url.Values)
			copyValues(r.Form, r.PostForm)
		}
		var newValues url.Values
		if r.URL != nil {
			var e error
			newValues, e = url.ParseQuery(r.URL.RawQuery)
			if err == nil {
				err = e
			}
		}
		if newValues == nil {
			newValues = make(url.Values)
		}
		if r.Form == nil {
			r.Form = newValues
		} else {
			copyValues(r.Form, newValues)
		}
	}
	return err
}

// ParseMultipartForm parses a request body as multipart/form-data.
// The whole request body is parsed and up to a total of maxMemory bytes of
// its file parts are stored in memory, with the remainder stored on
// disk in temporary files.
// ParseMultipartForm calls [Request.ParseForm] if necessary.
// If ParseForm returns an error, ParseMultipartForm returns it but also
// continues parsing the request body.
// After one call to ParseMultipartForm, subsequent calls have no effect.
func (r *Request) ParseMultipartForm(maxMemory int64) error {
	if r.MultipartForm == multipartByReader {
		return errors.New("http: multipart handled by MultipartReader")
	}
	var parseFormErr error
	if r.Form == nil {
		// Let errors in ParseForm fall through, and just
		// return it at the end.
		parseFormErr = r.ParseForm()
	}
	if r.MultipartForm != nil {
		return nil
	}

	mr, err := r.multipartReader(false)
	if err != nil {
		return err
	}

	f, err := mr.ReadForm(maxMemory)
	if err != nil {
		return err
	}

	if r.PostForm == nil {
		r.PostForm = make(url.Values)
	}
	for k, v := range f.Value {
		r.Form[k] = append(r.Form[k], v...)
		// r.PostForm should also be populated. See Issue 9305.
		r.PostForm[k] = append(r.PostForm[k], v...)
	}

	r.MultipartForm = f

	return parseFormErr
}

// FormValue returns the first value for the named component of the query.
// The precedence order:
//  1. application/x-www-form-urlencoded form body (POST, PUT, PATCH only)
//  2. query parameters (always)
//  3. multipart/form-data form body (always)
//
// FormValue calls [Request.ParseMultipartForm] and [Request.ParseForm]
// if necessary and ignores any errors returned by these functions.
// If key is not present, FormValue returns the empty string.
// To access multiple values of the same key, call ParseForm and
// then inspect [Request.Form] directly.
func (r *Request) FormValue(key string) string {
	if r.Form == nil {
		r.ParseMultipartForm(defaultMaxMemory)
	}
	if vs := r.Form[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// PostFormValue returns the first value for the named component of the POST,
// PUT, or PATCH request body. URL query parameters are ignored.
// PostFormValue calls [Request.ParseMultipartForm] and [Request.ParseForm] if necessary and ignores
// any errors returned by these functions.
// If key is not present, PostFormValue returns the empty string.
func (r *Request) PostFormValue(key string) string {
	if r.PostForm == nil {
		r.ParseMultipartForm(defaultMaxMemory)
	}
	if vs := r.PostForm[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// FormFile returns the first file for the provided form key.
// FormFile calls [Request.ParseMultipartForm] and [Request.ParseForm] if necessary.
func (r *Request) FormFile(key string) (multipart.File, *multipart.FileHeader, error) {
	if r.MultipartForm == multipartByReader {
		return nil, nil, errors.New("http: multipart handled by MultipartReader")
	}
	if r.MultipartForm == nil {
		err := r.ParseMultipartForm(defaultMaxMemory)
		if err != nil {
			return nil, nil, err
		}
	}
	if r.MultipartForm != nil && r.MultipartForm.File != nil {
		if fhs := r.MultipartForm.File[key]; len(fhs) > 0 {
			f, err := fhs[0].Open()
			return f, fhs[0], err
		}
	}
	return nil, nil, ErrMissingFile
}

// PathValue 返回与请求匹配的 [ServeMux] 模式中命名路径通配符的值。如果请求未与模式匹配，或者模式中没有此类通配符，则返回空字符串。
func (r *Request) PathValue(name string) string {
	if i := r.patIndex(name); i >= 0 {
		return r.matches[i]
	}
	return r.otherValues[name]
}

// SetPathValue 将 name 设置为 value，以便后续对 r.PathValue(name) 的调用返回 value。
func (r *Request) SetPathValue(name, value string) {
	if i := r.patIndex(name); i >= 0 {
		r.matches[i] = value
	} else {
		if r.otherValues == nil {
			r.otherValues = map[string]string{}
		}
		r.otherValues[name] = value
	}
}

// patIndex 返回请求模式的命名通配符列表中的名称索引，如果没有此类名称，则返回 -1。
func (r *Request) patIndex(name string) int {
	// The linear search seems expensive compared to a map, but just creating the map
	// takes a lot of time, and most patterns will just have a couple of wildcards.
	if r.pat == nil {
		return -1
	}
	i := 0
	for _, seg := range r.pat.segments {
		if seg.wild && seg.s != "" {
			if name == seg.s {
				return i
			}
			i++
		}
	}
	return -1
}

func (r *Request) expectsContinue() bool {
	return hasToken(r.Header.get("Expect"), "100-continue")
}

func (r *Request) wantsHttp10KeepAlive() bool {
	if r.ProtoMajor != 1 || r.ProtoMinor != 0 {
		return false
	}
	return hasToken(r.Header.get("Connection"), "keep-alive")
}

func (r *Request) wantsClose() bool {
	if r.Close {
		return true
	}
	return hasToken(r.Header.get("Connection"), "close")
}

func (r *Request) closeBody() error {
	if r.Body == nil {
		return nil
	}
	return r.Body.Close()
}

func (r *Request) isReplayable() bool {
	if r.Body == nil || r.Body == NoBody || r.GetBody != nil {
		switch valueOrDefault(r.Method, "GET") {
		case "GET", "HEAD", "OPTIONS", "TRACE":
			return true
		}
		// The Idempotency-Key, while non-standard, is widely used to
		// mean a POST or other request is idempotent. See
		// https://golang.org/issue/19943#issuecomment-421092421
		if r.Header.has("Idempotency-Key") || r.Header.has("X-Idempotency-Key") {
			return true
		}
	}
	return false
}

// outgoingLength reports the Content-Length of this outgoing (Client) request.
// It maps 0 into -1 (unknown) when the Body is non-nil.
// outgoingLength 报告此 （Client） 传出请求的 Content-Length。
func (r *Request) outgoingLength() int64 {
	if r.Body == nil || r.Body == NoBody {
		return 0
	}
	if r.ContentLength != 0 {
		return r.ContentLength
	}
	return -1
}

// requestMethodUsuallyLacksBody reports whether the given request
// method is one that typically does not involve a request body.
// This is used by the Transport (via
// transferWriter.shouldSendChunkedRequestBody) to determine whether
// we try to test-read a byte from a non-nil Request.Body when
// Request.outgoingLength() returns -1. See the comments in
// shouldSendChunkedRequestBody.
func requestMethodUsuallyLacksBody(method string) bool {
	switch method {
	case "GET", "HEAD", "DELETE", "OPTIONS", "PROPFIND", "SEARCH":
		return true
	}
	return false
}

// requiresHTTP1 reports whether this request requires being sent on
// an HTTP/1 connection.
func (r *Request) requiresHTTP1() bool {
	return hasToken(r.Header.Get("Connection"), "upgrade") &&
		ascii.EqualFold(r.Header.Get("Upgrade"), "websocket")
}
