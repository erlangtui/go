// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP client. See RFC 7230 through 7235.
//
// This is the high-level Client interface.
// The low-level implementation is in transport.go.

package http

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http/internal/ascii"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Client 是 http 客户端的结构，其零值 [DefaultClient] 是一个可用的客户端，使用 [DefaultTransport]
//
// [Client.Transport] 通常具有内部状态 （缓存的 TCP 连接） ，因此应重用 Client，而不是根据需要创建 Client。
// 客户端可以安全地供多个 goroutine 同时使用。
//
// 客户端比 [RoundTripper]（如 [Transport]）级别更高，并且还处理 HTTP 详细信息，如 Cookie 和重定向。
//
// 当跟踪重定向时，客户端将转发在初始 [Request] 上设置的所有标头，但以下情况除外：
// - 将“Authorization”、“WWW-Authenticate”和“Cookie”等敏感标头转发到不受信任的目标时。
// 当重定向到不是子域匹配或与初始域完全匹配的域时，这些标头将被忽略。
// 例如，从“foo.com”重定向到“foo.com”或“sub.foo.com”将转发敏感标头，但重定向到“bar.com”则不会。
//
// - 使用非零 cookie Jar 转发“Cookie”标头时。由于每次重定向都可能改变 cookie jar 的状态，因此重定向可能会更改初始请求中设置的 cookie。
// 在转发“Cookie”标头时，任何突变的 cookie 都将被省略，并期望 Jar 将插入那些具有更新值的突变 cookie（假设源匹配）。
// 如果 Jar 为 nil，则初始 cookie 将不加更改地转发。
type Client struct {
	// Transport 指定了发出单个 HTTP 请求的机制。如果为 nil，则使用 DefaultTransport。
	Transport RoundTripper

	// CheckRedirect 指定用于处理重定向的策略。
	// 如果 CheckRedirect 不是 nil，则客户端会在遵循 HTTP 重定向之前调用它。
	// 参数 req 和 via 是即将到来的请求和已经发出的请求，最早的在前。
	// 如果 CheckRedirect 返回错误，则 Client 的 Get 方法将返回前一个 Response（其 Body 关闭）和 CheckRedirect 的错误（包装在 url.Error），而不是发出 Request req。
	// 作为一种特殊情况，如果 CheckRedirect 返回 ErrUseLastResponse，则返回的最新响应体的 body 未关闭，并返回 nil 错误。
	// 如果 CheckRedirect 为 nil，则客户端使用其默认策略，即在连续 10 个请求后停止。
	CheckRedirect func(req *Request, via []*Request) error

	// Jar 指定 cookie jar。
	// Jar 用于将相关 cookie 插入到每个出站请求中，并使用每个入站响应的 cookie 值进行更新。
	// 对于客户遵循的每个重定向，都会咨询 Jar。如果 Jar 为 nil，则仅在请求中明确设置了 cookie 时才会发送 cookie。
	Jar CookieJar

	// Timeout 指定此客户端发出的请求的时间限制。超时包括连接时间、任何重定向和读取响应体。
	// 计时器在 Get、Head、Post 或 Do 返回后保持运行状态，并将中断对 Response.Body 的读取。
	// Timeout 为零表示没有超时。
	// 客户端取消对底层传输的请求，就像请求的上下文已结束一样。
	// 为了兼容，客户端还将在 Transport 上使用已弃用的 CancelRequest 方法（如果找到）。
	// 新的 RoundTripper 实现应使用请求的 Context 进行取消，而不是实现 CancelRequest。
	Timeout time.Duration
}

// DefaultClient 是默认的 [Client]，由 [Get]、[Head] 和 [Post] 使用.
var DefaultClient = &Client{}

// RoundTripper 是一个接口，表示执行单个 HTTP 事务的能力，获取给定 [请求] 的 [响应]。
// RoundTripper 必须可以安全地供多个 goroutine 同时使用。
type RoundTripper interface {
	// RoundTrip 执行单个 HTTP 事务，并返回所提供请求的 Response。
	// RoundTrip 不应尝试解释响应。具体而言，如果 RoundTrip 获得了响应，则无论响应的 HTTP 状态代码如何，它都必须返回 err == nil。
	// 对于未能获取响应，应保留一个非 nil err。同样，RoundTrip 不应尝试处理更高级别的协议详细信息，例如重定向、身份验证或 Cookie。
	// RoundTrip 不应修改请求，但使用和关闭请求的正文除外。RoundTrip 可能会在单独的 goroutine 中读取请求的字段。
	// 在关闭响应体之前，调用方不应更改或重用请求。RoundTrip 必须始终关闭 body，包括在出现错误时，但根据实现的不同，
	// 即使在 RoundTrip 返回后，也可以在单独的 goroutine 中执行此操作。
	// 这意味着，想要将 body 重用于后续请求的调用者必须安排等待 Close 调用，然后再执行此操作。
	// 必须初始化 Request 的 URL 和 Header 字段。
	RoundTrip(*Request) (*Response, error)
}

// 如果 lastReq 协议是 https 并且 newReq 协议是 http，则 refererForURL 返回一个没有任何身份验证信息的引用者或空字符串。
// 如果明确设置了 referer，则将继续使用它
func refererForURL(lastReq, newReq *url.URL, explicitRef string) string {
	// https://tools.ietf.org/html/rfc7231#section-5.5.2
	//   "Clients SHOULD NOT include a Referer header field in a
	//    (non-secure) HTTP request if the referring page was
	//    transferred with a secure protocol."
	if lastReq.Scheme == "https" && newReq.Scheme == "http" {
		return ""
	}
	if explicitRef != "" {
		return explicitRef
	}

	referer := lastReq.String()
	if lastReq.User != nil {
		// This is not very efficient, but is the best we can
		// do without:
		// - introducing a new method on URL
		// - creating a race condition
		// - copying the URL struct manually, which would cause
		//   maintenance problems down the line
		auth := lastReq.User.String() + "@"
		referer = strings.Replace(referer, auth, "", 1)
	}
	return referer
}

// 仅当 err ！= nil 时，didTimeout 才为非 nil。
// 这个函数主要功能是发送HTTP请求并处理与之相关的Cookie。以下是高层次的解释：
//
// 1. **检查Cookie Jar**: 如果客户端(`c`)配置了Cookie Jar（用于存储和管理Cookie的容器），函数会遍历Jar中与请求URL相关的Cookie，并将它们添加到请求(`req`)中。
//
// 2. **实际发送请求**: 函数调用嵌套的`send`方法（假设是内部或同包中定义的另一个函数），传入请求、客户端的传输层（由`c.transport()`获取）和截止时间(`deadline`)。这个调用实际执行网络请求，并返回响应(`resp`)、是否超时的函数(`didTimeout`)和可能的错误(`err`)。
//
// 3. **错误处理**: 如果在发送请求过程中遇到错误，函数直接返回错误信息，以及超时检查函数（如果已超时）和错误本身。
//
// 4. **更新Cookie Jar**: 请求响应后，如果客户端有Cookie Jar，函数会检查响应中携带的Cookie。如果有新的Cookie，它们会被添加到Jar中，与请求的URL相关联，以维持会话状态。
//
// 5. **最终返回**: 如果一切顺利，函数返回响应、一个总是返回`false`的超时检查函数（因为如果成功，就不会超时）和`nil`错误。
func (c *Client) send(req *Request, deadline time.Time) (resp *Response, didTimeout func() bool, err error) {
	if c.Jar != nil {
		// Jar 用于将相关 cookie 插入到每个出站请求中
		for _, cookie := range c.Jar.Cookies(req.URL) {
			req.AddCookie(cookie)
		}
	}
	resp, didTimeout, err = send(req, c.transport(), deadline)
	if err != nil {
		return nil, didTimeout, err
	}
	if c.Jar != nil {
		// 并使用每个入站响应的 cookie 值进行更新 Jar
		if rc := resp.Cookies(); len(rc) > 0 {
			c.Jar.SetCookies(req.URL, rc)
		}
	}
	return resp, nil, nil
}

// 获取超时时间
func (c *Client) deadline() time.Time {
	if c.Timeout > 0 {
		return time.Now().Add(c.Timeout)
	}
	return time.Time{}
}

// 获取 Transport
func (c *Client) transport() RoundTripper {
	if c.Transport != nil {
		return c.Transport
	}
	return DefaultTransport
}

// ErrSchemeMismatch 当服务器向 HTTPS 客户端返回 HTTP 响应时，将返回 ErrSchemeMismatch。
var ErrSchemeMismatch = errors.New("http: server gave HTTP response to HTTPS client")

// send 发出 HTTP 请求。调用者应关闭 resp.Body 从中读完后
func send(ireq *Request, rt RoundTripper, deadline time.Time) (resp *Response, didTimeout func() bool, err error) {
	req := ireq // req is either the original request, or a modified fork

	if rt == nil {
		req.closeBody()
		return nil, alwaysFalse, errors.New("http: no Client.Transport or DefaultTransport")
	}

	if req.URL == nil {
		req.closeBody()
		return nil, alwaysFalse, errors.New("http: nil Request.URL")
	}

	if req.RequestURI != "" {
		req.closeBody()
		return nil, alwaysFalse, errors.New("http: Request.RequestURI can't be set in client requests")
	}

	// forkReq 在第一次调用 req 时将 req 分叉为 ireq 的浅层克隆。
	forkReq := func() {
		if ireq == req {
			req = new(Request)
			*req = *ireq // shallow clone
		}
	}

	// send 的大多数调用方（Get、Post 等）不需要 Headers，使其未初始化。不过，我们向 Transport 保证，这已经初始化了。
	if req.Header == nil {
		forkReq()
		req.Header = make(Header)
	}

	// 根据 url 设置 header 中的授权信息
	if u := req.URL.User; u != nil && req.Header.Get("Authorization") == "" {
		username := u.Username()
		password, _ := u.Password()
		forkReq()
		req.Header = cloneOrMakeHeader(ireq.Header)
		req.Header.Set("Authorization", "Basic "+basicAuth(username, password))
	}

	if !deadline.IsZero() {
		forkReq()
	}
	stopTimer, didTimeout := setRequestCancel(req, rt, deadline)

	resp, err = rt.RoundTrip(req)
	if err != nil {
		stopTimer()
		if resp != nil {
			log.Printf("RoundTripper returned a response & error; ignoring response")
		}
		if tlsErr, ok := err.(tls.RecordHeaderError); ok {
			// 如果我们得到一个错误的 TLS 记录头，请检查响应是否看起来像 HTTP，并给出一个更有用的错误。
			// See golang.org/issue/11111.
			if string(tlsErr.RecordHeader[:]) == "HTTP/" {
				// https 请求，返回了 http 响应
				err = ErrSchemeMismatch
			}
		}
		return nil, didTimeout, err
	}
	if resp == nil {
		return nil, didTimeout, fmt.Errorf("http: RoundTripper implementation (%T) returned a nil *Response with a nil error", rt)
	}
	if resp.Body == nil {
		// Body 字段上的文档说“http Client 和 Transport 保证 Body 始终为非 nil，即使在没有 body 的响应或具有零长度 body 的响应上也是如此。
		// 遗憾的是，我们没有为任意 RoundTripper 实现记录相同的约束，并且野外的 RoundTripper 实现（主要在测试中）假设它们可以使用 nil Body 来表示空的 Body（类似于 Request.Body）。
		// (See https://golang.org/issue/38095.)
		// 如果 ContentLength 允许 Body 为空，请在此处填充一个空值，以确保它不是 nil。
		if resp.ContentLength > 0 && req.Method != "HEAD" {
			return nil, didTimeout, fmt.Errorf("http: RoundTripper implementation (%T) returned a *Response with content length %d but a nil Body", rt, resp.ContentLength)
		}
		resp.Body = io.NopCloser(strings.NewReader(""))
	}
	if !deadline.IsZero() {
		// 如果设置了超时时间，则需要在响应体中添加 stopTimer 和 didTimeout 函数，因为超时时间是包含读取响应体的
		resp.Body = &cancelTimerBody{
			stop:          stopTimer,
			rc:            resp.Body,
			reqDidTimeout: didTimeout,
		}
	}
	return resp, nil, nil
}

// timeBeforeContextDeadline 报告非零时间 t 是否早于 ctx 的截止时间（如果有）。
// 如果 ctx 没有截止日期，它将始终报告为 true（截止日期被认为是无限的）
func timeBeforeContextDeadline(t time.Time, ctx context.Context) bool {
	d, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return t.Before(d)
}

// knownRoundTripperImpl 报告 rt 是否是由 Go 团队维护的 RoundTripper，并且已知它实现了最新的可选语义（尤其是上下文）。
// Request 用于检查此特定请求是否正在使用备用协议，在这种情况下，我们需要检查该协议的 RoundTripper。
func knownRoundTripperImpl(rt RoundTripper, req *Request) bool {
	switch t := rt.(type) {
	case *Transport:
		if altRT := t.alternateRoundTripper(req); altRT != nil {
			return knownRoundTripperImpl(altRT, req)
		}
		return true
	case *http2Transport, http2noDialH2RoundTripper:
		return true
	}
	// 这样做，误报的可能性非常小。它不会检测我们的 golang.orgxnethttp2.Transport，而是可能会在不同的 http2 包中检测到 Transport 类型。
	// 但我一无所知，如果传输不支持上下文，唯一的问题是一些暂时泄露的 goroutines。所以这是一个足够好的启发式方法：
	if reflect.TypeOf(rt).String() == "*http2.Transport" {
		return true
	}
	return false
}

// setRequestCancel 为给定的 Request 设置取消功能，确保它在指定的截止时间前完成。
// 该函数返回两个函数：一个用于停止定时器，另一个用于检查请求是否超时。
// 如果请求的截止时间已设置，函数将创建一个新的带截止时间的上下文，并根据需要设置取消函数。
// 对于旧的 RoundTripper 实现，它也提供了取消请求的兼容性。
// setRequestCancel 如果 deadline 不为零，则设置 req.Cancel 并向 req 添加截止日期上下文。
// RoundTripper 的类型用于确定是否应使用旧版 CancelRequest 行为。
// 作为背景，有三种方法可以取消请求：第一种是 Transport.CancelRequest。（已弃用）
// 第二个是 Request.Cancel。第三个是 Request.Context。此函数填充第二个和第三个，并在需要时使用第一个。
func setRequestCancel(req *Request, rt RoundTripper, deadline time.Time) (stopTimer func(), didTimeout func() bool) {
	// 如果截止时间为空，直接返回空函数
	if deadline.IsZero() {
		return nop, alwaysFalse
	}
	// 检查 RoundTripper 类型以决定是否需要特殊处理
	knownTransport := knownRoundTripperImpl(rt, req)
	oldCtx := req.Context()

	// 如果请求没有取消函数且是我们知道的 RoundTripper 类型，处理上下文截止时间
	if req.Cancel == nil && knownTransport {
		// 如果他们已经有即将过期的 Request.Context，则不执行任何操作：
		if !timeBeforeContextDeadline(deadline, oldCtx) {
			return nop, alwaysFalse
		}

		var cancelCtx func()
		req.ctx, cancelCtx = context.WithDeadline(oldCtx, deadline)
		return cancelCtx, func() bool { return time.Now().After(deadline) }
	}
	// 为请求设置或更新上下文，并准备取消逻辑
	initialReqCancel := req.Cancel // the user's original Request.Cancel, if any

	var cancelCtx func()
	if timeBeforeContextDeadline(deadline, oldCtx) {
		req.ctx, cancelCtx = context.WithDeadline(oldCtx, deadline)
	}

	cancel := make(chan struct{})
	req.Cancel = cancel

	// 定义取消逻辑，并准备停止定时器的逻辑
	doCancel := func() {
		// The second way in the func comment above:
		close(cancel)
		// The first way, used only for RoundTripper
		// implementations written before Go 1.5 or Go 1.6.
		type canceler interface{ CancelRequest(*Request) }
		if v, ok := rt.(canceler); ok {
			v.CancelRequest(req)
		}
	}

	stopTimerCh := make(chan struct{})
	var once sync.Once
	stopTimer = func() {
		once.Do(func() {
			close(stopTimerCh)
			if cancelCtx != nil {
				cancelCtx()
			}
		})
	}

	timer := time.NewTimer(time.Until(deadline))
	var timedOut atomic.Bool

	// 启动一个goroutine来监听取消信号、超时和停止信号
	go func() {
		select {
		case <-initialReqCancel:
			doCancel()
			timer.Stop()
		case <-timer.C:
			timedOut.Store(true)
			doCancel()
		case <-stopTimerCh:
			timer.Stop()
		}
	}()

	return stopTimer, timedOut.Load
}

// See 2 (end of page 4) https://www.ietf.org/rfc/rfc2617.txt
// “为了接收授权，客户端在凭据的 base64 编码字符串中发送用户 ID 和密码，并用单冒号 （”：“） 字符分隔。”它并不意味着要进行 urlencoded。
// basicAuth 生成基本认证的 Base64 编码字符串
// 参数:
//
//	username: 用户名字符串
//	password: 密码字符串
//
// 返回:
//
//	返回将用户名和密码以冒号连接后，经过 Base64 编码的字符串，用于HTTP基本认证
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// Get 使用 DefaultClient 向指定的 URL 发出 GET。
// 如果响应是以下重定向代码之一，则 Get 将跟随重定向，最多 10 个重定向：
//
//	301 (Moved Permanently)
//	302 (Found)
//	303 (See Other)
//	307 (Temporary Redirect)
//	308 (Permanent Redirect)
//
// 如果重定向过多或存在 HTTP 协议错误，则返回错误。非 2xx 响应不会导致错误。
// 任何返回的错误都将是 [*url.Error]。如果请求超时，url.Error 值的 Timeout 方法将报告 true。
//
// 当返回的错误为空时，resp 总是包含一个非空的 body，调用者应该在读完数据后关闭 body
// 若要使用自定义标头发出请求，请使用 [NewRequest] 并 DefaultClient.Do。
// 若使用指定的上下文发出请求。Context，请使用 [NewRequestWithContext] 并 DefaultClient.Do。
func Get(url string) (resp *Response, err error) {
	return DefaultClient.Get(url)
}

// Get 向指定的 URL 发出 GET。如果响应是以下重定向代码之一，则 Get 会在调用 [Client.CheckRedirect] 函数后跟踪重定向：
//
//	301 (Moved Permanently)
//	302 (Found)
//	303 (See Other)
//	307 (Temporary Redirect)
//	308 (Permanent Redirect)
//
// 如果重定向过多或存在 HTTP 协议错误，则返回错误。非 2xx 响应不会导致错误。
// 任何返回的错误都将是 [*url.Error]。如果请求超时，url.Error 值的 Timeout 方法将报告 true。
//
// 当返回的错误为空时，resp 总是包含一个非空的 body，调用者应该在读完数据后关闭 body
// 若要使用自定义标头发出请求，请使用 [NewRequest] 并 DefaultClient.Do。
// 若使用指定的上下文发出请求。Context，请使用 [NewRequestWithContext] 并 DefaultClient.Do。
func (c *Client) Get(url string) (resp *Response, err error) {
	req, err := NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func alwaysFalse() bool { return false }

// ErrUseLastResponse 可以由 Client.CheckRedirect 钩子返回，以控制重定向的处理方式。
// 如果返回，则不会发送下一个请求，并且返回最近的响应，而其 body 未关闭。
var ErrUseLastResponse = errors.New("net/http: use last response")

// checkRedirect 调用用户配置的 CheckRedirect 函数或默认值。
func (c *Client) checkRedirect(req *Request, via []*Request) error {
	fn := c.CheckRedirect
	if fn == nil {
		fn = defaultCheckRedirect
	}
	return fn(req, via)
}

// redirectBehavior 描述了当客户端遇到来自服务器的 3xx 状态代码时应该发生的情况。
func redirectBehavior(reqMethod string, resp *Response, ireq *Request) (redirectMethod string, shouldRedirect, includeBody bool) {
	switch resp.StatusCode {
	case 301, 302, 303:
		redirectMethod = reqMethod
		shouldRedirect = true
		includeBody = false

		// RFC 2616 allowed automatic redirection only with GET and
		// HEAD requests. RFC 7231 lifts this restriction, but we still
		// restrict other methods to GET to maintain compatibility.
		// See Issue 18570.
		if reqMethod != "GET" && reqMethod != "HEAD" {
			redirectMethod = "GET"
		}
	case 307, 308:
		redirectMethod = reqMethod
		shouldRedirect = true
		includeBody = true

		if ireq.GetBody == nil && ireq.outgoingLength() != 0 {
			// 我们有一个请求体，307 308 需要重新发送它，但未定义 GetBody。
			// 因此，只需将此响应返回给用户，而不是像我们在 Go 1.7 及更早版本中所做的那样。
			shouldRedirect = false
		}
	}
	return redirectMethod, shouldRedirect, includeBody
}

// urlErrorOp 返回  (*url.Error).Op 用于提供的 (*Request).Method 的值。
func urlErrorOp(method string) string {
	if method == "" {
		return "Get"
	}
	if lowerMethod, ok := ascii.ToLower(method); ok {
		return method[:1] + lowerMethod[1:]
	}
	return method
}

// Do 发送 HTTP 请求并返回 HTTP 响应，遵循客户端上配置的策略（例如重定向、cookie、身份验证）
// 如果由客户端策略（如 CheckRedirect）或无法读 HTTP（如网络连接问题）引起，则返回错误。非 2xx 状态代码不会导致错误。
// 如果返回的错误为 nil，则 [Response] 将包含一个非 nil Body，用户应关闭该 Body。
// 如果 Body 同时未读取到 EOF 并关闭，则 [Client] 的底层 [RoundTripper]（通常是 [Transport]）
// 可能无法重新使用与服务器的持久 TCP 连接来执行后续的“保持活动”请求。
//
// 如果请求 Body 不是 nil，则将被底层的 Transport 关闭，即使在出错时也是如此。
// 在 Do 返回后，Body 可能会异步关闭。如果出错，任何响应都可以忽略。
// 仅当 CheckRedirect 失败时，才会发生具有非 nil 错误的非 nil 响应，即使如此，返回的 [Response.Body] 也已关闭。
//
// 通常，将使用 [Get]、[Post] 或 [PostForm] 而不是 Do。
//
// 如果服务器使用重定向进行回复，则客户端首先使用 CheckRedirect 函数来确定是否应遵循重定向。
// 如果允许，301、302 或 303 重定向会导致后续请求使用 HTTP 方法 GET（如果原始请求是 HEAD，则使用 HEAD），而不携带 body。
// 如果定义了 [Request.GetBody] 函数，则 307 或 308 重定向会保留原始 HTTP 方法和 body。
// [NewRequest] 函数会自动为常见的标准库 body 类型设置 GetBody。
// 任何返回的错误都将是 [*url.Error]，如果请求超时，url.Error 值的 Timeout 方法将报告 true。
func (c *Client) Do(req *Request) (*Response, error) {
	return c.do(req)
}

var testHookClientDoResult func(retres *Response, reterr error)

func (c *Client) do(req *Request) (retres *Response, reterr error) {
	if testHookClientDoResult != nil {
		defer func() { testHookClientDoResult(retres, reterr) }()
	}
	if req.URL == nil {
		req.closeBody()
		return nil, &url.Error{
			Op:  urlErrorOp(req.Method),
			Err: errors.New("http: nil Request.URL"),
		}
	}
	_ = *c // 如果 c 为 nil 提前 panic; see go.dev/issue/53521

	var (
		deadline      = c.deadline()
		reqs          []*Request // 记录每次重定向的请求
		resp          *Response
		copyHeaders   = c.makeHeadersCopier(req)
		reqBodyClosed = false // 请求体是否已经被关闭

		// 重定向腥味
		redirectMethod string
		includeBody    bool
	)
	uerr := func(err error) error {
		// 请求体可能已经被 c.send() 关闭
		// the body may have been closed already by c.send()
		if !reqBodyClosed {
			req.closeBody()
		}
		var urlStr string
		if resp != nil && resp.Request != nil {
			urlStr = stripPassword(resp.Request.URL)
		} else {
			urlStr = stripPassword(req.URL)
		}
		return &url.Error{
			Op:  urlErrorOp(reqs[0].Method),
			URL: urlStr,
			Err: err,
		}
	}
	for {
		// 对于除第一个请求之外的所有请求，创建下一个请求跃点并替换 req。
		if len(reqs) > 0 {
			// 处理重定向请求
			loc := resp.Header.Get("Location")
			if loc == "" {
				// 虽然大多数 3xx 响应都包含 Location，但这不是必需的，并且在野外观察到了没有 Location 的 3xx 响应。请参阅问题 17773 和 49281。
				return resp, nil
			}
			u, err := req.URL.Parse(loc)
			if err != nil {
				resp.closeBody()
				return nil, uerr(fmt.Errorf("failed to parse Location header %q: %v", loc, err))
			}
			host := ""
			if req.Host != "" && req.Host != req.URL.Host {
				// If the caller specified a custom Host header and the
				// redirect location is relative, preserve the Host header
				// through the redirect. See issue #22233.
				if u, _ := url.Parse(loc); u != nil && !u.IsAbs() {
					host = req.Host
				}
			}
			ireq := reqs[0]
			req = &Request{
				Method:   redirectMethod,
				Response: resp,
				URL:      u,
				Header:   make(Header),
				Host:     host,
				Cancel:   ireq.Cancel,
				ctx:      ireq.ctx,
			}
			if includeBody && ireq.GetBody != nil {
				req.Body, err = ireq.GetBody()
				if err != nil {
					resp.closeBody()
					return nil, uerr(err)
				}
				req.ContentLength = ireq.ContentLength
			}

			// Copy original headers before setting the Referer,
			// in case the user set Referer on their first request.
			// If they really want to override, they can do it in
			// their CheckRedirect func.
			copyHeaders(req)

			// 如果它不是 https->http，请将最新请求 URL 中的 Referer 标头添加到新 URL：
			if ref := refererForURL(reqs[len(reqs)-1].URL, req.URL, req.Header.Get("Referer")); ref != "" {
				req.Header.Set("Referer", ref)
			}
			err = c.checkRedirect(req, reqs)

			// Sentinel 错误，允许用户选择上一个响应，而不关闭其正文。请参阅问题 10069。
			if err == ErrUseLastResponse {
				return resp, nil
			}

			// Close the previous response's body. But
			// read at least some of the body so if it's
			// small the underlying TCP connection will be
			// re-used. No need to check for errors: if it
			// fails, the Transport won't reuse it anyway.
			const maxBodySlurpSize = 2 << 10
			if resp.ContentLength == -1 || resp.ContentLength <= maxBodySlurpSize {
				io.CopyN(io.Discard, resp.Body, maxBodySlurpSize)
			}
			resp.Body.Close()

			if err != nil {
				// Special case for Go 1 compatibility: return both the response
				// and an error if the CheckRedirect function failed.
				// See https://golang.org/issue/3795
				// The resp.Body has already been closed.
				ue := uerr(err)
				ue.(*url.Error).URL = loc
				return resp, ue
			}
		}

		reqs = append(reqs, req)
		var err error
		var didTimeout func() bool
		if resp, didTimeout, err = c.send(req, deadline); err != nil {
			// c.send() always closes req.Body
			reqBodyClosed = true
			if !deadline.IsZero() && didTimeout() {
				err = &timeoutError{err.Error() + " (Client.Timeout exceeded while awaiting headers)"}
			}
			return nil, uerr(err)
		}

		var shouldRedirect bool
		redirectMethod, shouldRedirect, includeBody = redirectBehavior(req.Method, resp, reqs[0])
		if !shouldRedirect {
			return resp, nil
		}

		req.closeBody()
	}
}

// makeHeadersCopier 创建一个函数，该函数从初始请求 ireq 复制请求头。
// 对于每个重定向，都必须调用此函数，以便它可以将请求头复制到即将到来的 Request 中。
func (c *Client) makeHeadersCopier(ireq *Request) func(*Request) {
	// 要复制的标头来自最初始的请求。我们使用一个封闭的回调来保留对这些原始头的引用。
	var (
		ireqhdr  = cloneOrMakeHeader(ireq.Header)
		icookies map[string][]*Cookie
	)
	if c.Jar != nil && ireq.Header.Get("Cookie") != "" {
		icookies = make(map[string][]*Cookie)
		for _, c := range ireq.Cookies() {
			icookies[c.Name] = append(icookies[c.Name], c)
		}
	}

	preq := ireq // The previous request
	return func(req *Request) {
		// If Jar is present and there was some initial cookies provided
		// via the request header, then we may need to alter the initial
		// cookies as we follow redirects since each redirect may end up
		// modifying a pre-existing cookie.
		//
		// Since cookies already set in the request header do not contain
		// information about the original domain and path, the logic below
		// assumes any new set cookies override the original cookie
		// regardless of domain or path.
		//
		// See https://golang.org/issue/17494
		if c.Jar != nil && icookies != nil {
			var changed bool
			resp := req.Response // The response that caused the upcoming redirect
			for _, c := range resp.Cookies() {
				if _, ok := icookies[c.Name]; ok {
					delete(icookies, c.Name)
					changed = true
				}
			}
			if changed {
				ireqhdr.Del("Cookie")
				var ss []string
				for _, cs := range icookies {
					for _, c := range cs {
						ss = append(ss, c.Name+"="+c.Value)
					}
				}
				slices.Sort(ss) // Ensure deterministic headers
				ireqhdr.Set("Cookie", strings.Join(ss, "; "))
			}
		}

		// Copy the initial request's Header values
		// (at least the safe ones).
		for k, vv := range ireqhdr {
			if shouldCopyHeaderOnRedirect(k, preq.URL, req.URL) {
				req.Header[k] = vv
			}
		}

		preq = req // Update previous Request with the current request
	}
}

// 默认超过 10 次后不再进行重定向请求
func defaultCheckRedirect(req *Request, via []*Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// Post 向指定的 URL 发出 POST 请求。调用者在读完 resp.Body 后应该将其关闭。
// 如果提供的 body 是 [io.Closer]，它在请求后关闭。
// Post 是 DefaultClient.Post 的包装器。
// 若要设置自定义标头，请使用 [NewRequest] 和 DefaultClient.Do。
// 有关如何处理重定向的详细信息，请参阅 [Client.Do] 方法文档。
// 若要使用指定的上下文发出请求，请使用 [NewRequestWithContext] 并 DefaultClient.Do。
func Post(url, contentType string, body io.Reader) (resp *Response, err error) {
	return DefaultClient.Post(url, contentType, body)
}

// Post 向指定的 URL 发出 POST 请求。调用者在读完 resp.Body 后应该将其关闭。
// 如果提供的 body 是 [io.Closer]，它在请求后关闭。
// Post 是 DefaultClient.Post 的包装器。
// 若要设置自定义标头，请使用 [NewRequest] 和 DefaultClient.Do。
// 有关如何处理重定向的详细信息，请参阅 [Client.Do] 方法文档。
// 若要使用指定的上下文发出请求，请使用 [NewRequestWithContext] 并 DefaultClient.Do。
func (c *Client) Post(url, contentType string, body io.Reader) (resp *Response, err error) {
	req, err := NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// PostForm 向指定的 URL 发出 POST 请求，数据的键和值以 URL 编码作为请求体。
// Content-Type 标头设置为 applicationx-www-form-urlencoded。若要设置其他标头，请使用 [NewRequest] 并 DefaultClient.Do。
// 当 err 为 nil 时，resp 始终包含非 nil 的 resp.Body。调用者在读完 resp.Body 后应该将其关闭。
// PostForm 是 DefaultClient.PostForm 的包装器。有关如何处理重定向的详细信息，请参阅 [Client.Do] 方法文档。
// 使用指定的 [context.Context]，使用 [NewRequestWithContext] 并 DefaultClient.Do。
func PostForm(url string, data url.Values) (resp *Response, err error) {
	return DefaultClient.PostForm(url, data)
}

// PostForm 向指定的 URL 发出 POST 请求，数据的键和值以 URL 编码作为请求体。
// Content-Type 标头设置为 applicationx-www-form-urlencoded。若要设置其他标头，请使用 [NewRequest] 并 DefaultClient.Do。
// 当 err 为 nil 时，resp 始终包含非 nil 的 resp.Body。调用者在读完 resp.Body 后应该将其关闭。
// PostForm 是 DefaultClient.PostForm 的包装器。有关如何处理重定向的详细信息，请参阅 [Client.Do] 方法文档。
// 使用指定的 [context.Context]，使用 [NewRequestWithContext] 并 DefaultClient.Do。
func (c *Client) PostForm(url string, data url.Values) (resp *Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

// Head 向指定的 URL 发出 HEAD。如果响应是以下重定向代码之一，则 Head 将跟踪重定向，最多 10 个重定向：
//
//	301 (Moved Permanently)
//	302 (Found)
//	303 (See Other)
//	307 (Temporary Redirect)
//	308 (Permanent Redirect)
//
// Head 是 DefaultClient.Head 的包装器
// 如果要使用指定的 [context.Context]，使用 [NewRequestWithContext] 并 DefaultClient.Do。
func Head(url string) (resp *Response, err error) {
	return DefaultClient.Head(url)
}

// Head 向指定的 URL 发出 HEAD。如果响应是以下重定向代码之一，则 Head 在调用 [Client.CheckRedirect] 函数后跟踪重定向：
//
//	301 (Moved Permanently)
//	302 (Found)
//	303 (See Other)
//	307 (Temporary Redirect)
//	308 (Permanent Redirect)
//
// 如果要使用指定的 [context.Context]，使用 [NewRequestWithContext] 并 DefaultClient.Do。
func (c *Client) Head(url string) (resp *Response, err error) {
	req, err := NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// CloseIdleConnections 关闭其 [Transport] 上的任何连接，这些以前请求的连接，但现在处于“保持活动”状态。它不会中断当前正在使用的任何连接。
// 如果 [Client.Transport] 没有 [Client.CloseIdleConnections] 方法，则此方法不执行任何操作。
func (c *Client) CloseIdleConnections() {
	type closeIdler interface {
		CloseIdleConnections()
	}
	if tr, ok := c.transport().(closeIdler); ok {
		tr.CloseIdleConnections()
	}
}

// cancelTimerBody 是一个 io.ReadCloser，它用两个功能包装了 rc：
//  1. 在读取错误或关闭时，将调用 stop 函数。
//  2. 读取失败时，如果 reqDidTimeout 为 true，则错误将被包装并标记为 net.Error 变现为超时的错误。
type cancelTimerBody struct {
	stop          func() // 停止 time.Timer，等待取消请求
	rc            io.ReadCloser
	reqDidTimeout func() bool
}

func (b *cancelTimerBody) Read(p []byte) (n int, err error) {
	n, err = b.rc.Read(p)
	if err == nil {
		return n, nil
	}
	if err == io.EOF {
		return n, err
	}
	if b.reqDidTimeout() {
		err = &timeoutError{err.Error() + " (Client.Timeout or context cancellation while reading body)"}
	}
	return n, err
}

func (b *cancelTimerBody) Close() error {
	err := b.rc.Close()
	b.stop()
	return err
}

func shouldCopyHeaderOnRedirect(headerKey string, initial, dest *url.URL) bool {
	switch CanonicalHeaderKey(headerKey) {
	case "Authorization", "Www-Authenticate", "Cookie", "Cookie2":
		// 允许将 auth/cookie 标头从“foo.com”发送到“sub.foo.com”。
		// 请注意，我们不会自动将所有 Cookie 发送到子域。此功能仅用于在初始传出客户端请求上明确设置的 Cookie。
		// 通过 CookieJar 机制自动添加的 Cookie 将继续遵循 Set-Cookie 设置的每个 Cookie 的范围。
		// 但是对于直接设置了 Cookie 标头的传出请求，我们不知道它们的范围，因此我们假设它是针对 .domain.com。

		ihost := idnaASCIIFromURL(initial)
		dhost := idnaASCIIFromURL(dest)
		return isDomainOrSubdomain(dhost, ihost)
	}
	// All other headers are copied:
	return true
}

// isDomainOrSubdomain 报告 sub 是否是父域的子域（或完全匹配）。这两个域都必须已经是规范形式。
func isDomainOrSubdomain(sub, parent string) bool {
	if sub == parent {
		return true
	}
	// 如果 sub 包含 ：，则它可能是一个 IPv6 地址（并且绝对不是主机名）。在这种情况下，请勿检查后缀，以避免与 IPv6 区域的内容匹配。
	// 例如，“::1%.www.example.com”不是“www.example.com”的子域。
	if strings.ContainsAny(sub, ":%") {
		return false
	}
	// 如果 sub 是“foo.example.com”，父是“example.com”，则表示 sub 必须以“.” 结尾。+家长。在不分配的情况下进行。
	if !strings.HasSuffix(sub, parent) {
		return false
	}
	return sub[len(sub)-len(parent)-1] == '.'
}

// 影藏掉 url 中的用户名
func stripPassword(u *url.URL) string {
	_, passSet := u.User.Password()
	if passSet {
		return strings.Replace(u.String(), u.User.String()+"@", u.User.Username()+":***@", 1)
	}
	return u.String()
}
