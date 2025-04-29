package gjallarhorn

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-radix"
	"github.com/kashari/gjallarhorn/binding"
	"github.com/kashari/golog"
)

// Wrapper for http.HandlerFunc
type Middleware func(http.HandlerFunc) http.HandlerFunc

// ctxKey is an unexported type for context keys.
type ctxKey string

// Context wraps the http response and request, and provides utility methods.
type Context struct {
	Writer  http.ResponseWriter
	Request *http.Request
}

// Param retrieves a path parameter from the request context.
func (c *Context) Param(key string) string {
	if params, ok := c.Request.Context().Value(ctxKey("params")).(map[string]string); ok {
		return params[key]
	}
	return ""
}

// ParamInt converts the parameter value to an int.
func (c *Context) ParamInt(key string) (int, error) {
	return strconv.Atoi(c.Param(key))
}

// ParamInt64 converts the parameter value to an int64.
func (c *Context) ParamInt64(key string) (int64, error) {
	return strconv.ParseInt(c.Param(key), 10, 64)
}

// ParamFloat64 converts the parameter value to a float64.
func (c *Context) ParamFloat64(key string) (float64, error) {
	return strconv.ParseFloat(c.Param(key), 64)
}

// ParamBool converts the parameter value to a bool.
func (c *Context) ParamBool(key string) (bool, error) {
	return strconv.ParseBool(c.Param(key))
}

// Query returns all query parameters.
func (c *Context) Query() map[string]interface{} {
	q := make(map[string]interface{})
	for key, vals := range c.Request.URL.Query() {
		if len(vals) > 0 {
			q[key] = vals[0]
		}
	}
	return q
}

// Body returns the request body as bytes.
func (c *Context) Body() []byte {
	body, _ := io.ReadAll(c.Request.Body)
	return body
}

// JsonBody decodes the request body into a map.
func (c *Context) JsonBody() map[string]interface{} {
	var body map[string]interface{}
	json.NewDecoder(c.Request.Body).Decode(&body)
	return body
}

// QueryParam returns a single query parameter.
func (c *Context) QueryParam(key string) string {
	return c.Request.URL.Query().Get(key)
}

// ShouldBindWith binds the passed struct pointer using the specified binding engine.
// See the binding package.
func (c *Context) ShouldBindWith(obj any, b binding.Binding) error {
	return b.Bind(c.Request, obj)
}

// BindJSON binds the request JSON to a given struct.
func (c *Context) BindJSON(v interface{}) error {
	return c.ShouldBindWith(v, binding.JSON)
}

// JSON sends a JSON response.
func (c *Context) JSON(status int, data interface{}) {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(status)
	json.NewEncoder(c.Writer).Encode(data)
}

// String sends a plain text response.
func (c *Context) String(status int, data string) {
	golog.Debug("RESPONSE: {}", data)
	c.Writer.Header().Set("Content-Type", "text/plain")
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(data))
}

// paramsKey is the key under which URL parameters are stored.
const paramsKey ctxKey = "params"

// route represents a registered route.
type route struct {
	method  string
	pattern string // e.g., "/users/:id"
	handler http.HandlerFunc
}

// Router is our HTTP router with integrated logging.
type Router struct {
	staticRoutes  *radix.Tree  // static routes stored by exact path
	dynamicRoutes []route      // routes with parameters (e.g., ":id")
	middlewares   []Middleware // middleware chain
	workerPool    *WorkerPool  // optional worker pool for concurrent handling
	rateLimiter   *RateLimiter // optional rate limiter on the critical path
}

func Heimdallr() *Router {
	r := &Router{
		staticRoutes:  radix.New(),
		dynamicRoutes: make([]route, 0),
		middlewares:   []Middleware{},
	}
	r.printStartupInfo()
	return r
}

// Use adds a middleware to the chain.
func (r *Router) Use(m Middleware) *Router {
	r.middlewares = append(r.middlewares, m)
	return r
}

// WithWorkerPool configures the router to use a worker pool.
func (r *Router) WithWorkerPool(poolSize int) *Router {
	r.workerPool = NewWorkerPool(poolSize)
	return r
}

// WithRateLimiter configures the router to use a rate limiter.
func (r *Router) WithRateLimiter(maxTokens int, refillInterval time.Duration) *Router {
	r.rateLimiter = NewRateLimiter(maxTokens, refillInterval)
	return r
}

// WithFileLogging configures the router to log to the specified file in addition to the console.
// If the file cannot be opened, it logs an error and leaves the existing logger intact.
func (r *Router) WithFileLogging(filePath string) *Router {
	err := golog.Init(filePath)
	if err != nil {
		golog.Error("Failed to open log file {}: {}}", filePath, err)
	} else {
		golog.Info("Logging to file {}", filePath)
	}

	return r
}

// Handle registers a new route.
func (r *Router) Handle(method, pattern string, handler http.HandlerFunc) *Router {
	rt := route{
		method:  method,
		pattern: pattern,
		handler: handler,
	}
	if !strings.ContainsAny(pattern, ":*") {
		r.staticRoutes.Insert(pattern, rt)
	} else {
		r.dynamicRoutes = append(r.dynamicRoutes, rt)
	}
	return r
}

// HandleFunc registers a route using a Context-based handler.
func (r *Router) HandleFunc(method, pattern string, handler func(*Context)) *Router {
	rt := route{
		method:  method,
		pattern: pattern,
		handler: func(w http.ResponseWriter, req *http.Request) {
			ctx := &Context{Writer: w, Request: req}
			handler(ctx)
		},
	}
	if !strings.ContainsAny(pattern, ":*") {
		r.staticRoutes.Insert(pattern, rt)
	} else {
		r.dynamicRoutes = append(r.dynamicRoutes, rt)
	}
	return r
}

func (r *Router) GET(pattern string, handler func(*Context)) *Router {
	return r.HandleFunc("GET", pattern, handler)
}

func (r *Router) POST(pattern string, handler func(*Context)) *Router {
	return r.HandleFunc(http.MethodPost, pattern, handler)
}

func (r *Router) PUT(pattern string, handler func(*Context)) *Router {
	return r.HandleFunc(http.MethodPut, pattern, handler)
}

func (r *Router) DELETE(pattern string, handler func(*Context)) *Router {
	return r.HandleFunc(http.MethodDelete, pattern, handler)
}

// ListRoutes returns a slice of strings describing all registered routes.
func (r *Router) ListRoutes() []string {
	var routes []string
	r.staticRoutes.Walk(func(path string, v interface{}) bool {
		rt := v.(route)
		routes = append(routes, rt.method+" "+rt.pattern)
		return false
	})
	for _, rt := range r.dynamicRoutes {
		routes = append(routes, rt.method+" "+rt.pattern)
	}
	return routes
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()

	if val, found := r.staticRoutes.Get(req.URL.Path); found {
		rt := val.(route)
		if rt.method == req.Method {
			r.executeHandler(w, req, rt.handler)
			golog.Info("(STATIC ROUTE) Request: {} {}, from: {} completed in {}", req.Method, req.URL.Path, req.RemoteAddr, time.Since(start))
			return
		}
		w.Header().Set("Allow", rt.method)
		http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
		golog.Warn("Method not allowed (static) {}", time.Since(start).String())
		return
	}

	for _, rt := range r.dynamicRoutes {
		if params, ok := matchPattern(rt.pattern, req.URL.Path); ok && rt.method == req.Method {
			ctx := context.WithValue(req.Context(), paramsKey, params)
			r.executeHandler(w, req.WithContext(ctx), rt.handler)
			golog.Info("(DYNAMIC ROUTE) Request: {} {}, from: {} completed in {}", req.Method, req.URL.Path, req.RemoteAddr, time.Since(start))
			return
		}
	}

	http.NotFound(w, req)
	golog.Warn("Route not found {}", time.Since(start).String())
}

// executeHandler runs the handler with the middleware chain and rate limiter.
func (r *Router) executeHandler(w http.ResponseWriter, req *http.Request, handler http.HandlerFunc) {
	finalHandler := handler
	for i := len(r.middlewares) - 1; i >= 0; i-- {
		finalHandler = r.middlewares[i](finalHandler)
	}

	if r.rateLimiter != nil && !r.rateLimiter.Allow() {
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	}

	if r.workerPool != nil {
		done := make(chan struct{})
		err := r.workerPool.Submit(func() {
			finalHandler(w, req)
			close(done)
		})
		if err != nil {
			http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		<-done // wait for completion
	} else {
		finalHandler(w, req)
	}
}

// Start launches the HTTP server on the specified port after printing full configuration.
func (r *Router) Start(port string) error {
	r.printConfiguration()
	golog.Info("Starting server in port {}", port)
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		IdleTimeout:  90 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return server.ListenAndServe()
}

// printStartupInfo prints the HEIMDALL logo at router initialization.
func (r *Router) printStartupInfo() {
	// A large, well-formatted HEIMDALL logo.
	logo := `
            __       .__  .__               .__                          
   ____    |__|____  |  | |  | _____ _______|  |__   ___________  ____   
  / ___\   |  \__  \ |  | |  | \__  \\_  __ \  |  \ /  _ \_  __ \/    \  
 / /_/  >  |  |/ __ \|  |_|  |__/ __ \|  | \/   Y  (  <_> )  | \/   |  \ 
 \___  /\__|  (____  /____/____(____  /__|  |___|  /\____/|__|  |___|  / 
/_____/\______|    \/               \/           \/                  \/  

			gjållårhðrñ - A simple HTTP router for Go
`
	golog.Debug(logo)
}

// printConfiguration logs all startup configuration details.
func (r *Router) printConfiguration() {
	// Log registered routes.
	golog.Info("-------------------------- Registered Routes ---------------------------")
	for _, rt := range r.ListRoutes() {
		golog.Info("Route " + rt)
	}
	golog.Info("-------------------------- Registered Routes ---------------------------")

	// Rate limiter configuration.
	if r.rateLimiter != nil {
		golog.Info("Rate Limiter Configuration MAX_TOKENS: {} REFILL_INTERVAL: {}", r.rateLimiter.maxTokens, r.rateLimiter.refillInterval)
	} else {
		golog.Info("Rate Limiter not configured")
	}
	// Worker pool configuration.
	if r.workerPool != nil {
		golog.Info("Worker Pool Configuration SIZE: {}", r.workerPool.size)
	} else {
		golog.Info("Worker Pool not configured")
	}

	if len(r.middlewares) > 0 {
		golog.Info("-------------------------- Middleware Chain ---------------------------")
		golog.Info("--")
		for i, mw := range r.middlewares {
			golog.Info("Middleware {}: {}", i, getFunctionName(mw))
		}
		golog.Info("--")
		golog.Info("-------------------------- Middleware Chain ---------------------------")
	}

}

// matchPattern compares a route pattern with a request path.
func matchPattern(pattern, path string) (map[string]string, bool) {
	patternParts := splitPath(pattern)
	pathParts := splitPath(path)
	if len(patternParts) != len(pathParts) {
		return nil, false
	}
	params := make(map[string]string)
	for i, part := range patternParts {
		if len(part) > 0 && part[0] == ':' {
			key := part[1:]
			params[key] = pathParts[i]
		} else if part != pathParts[i] {
			return nil, false
		}
	}
	return params, true
}

// splitPath splits a URL path into non-empty segments.
func splitPath(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
}

// getFunctionName returns the name of a function (used for middleware identification).
func getFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

// WorkerPool manages a pool of goroutines.
type WorkerPool struct {
	tasks chan func()
	wg    sync.WaitGroup
	size  int
}

// NewWorkerPool creates a new worker pool with the given size.
// It sets the channel buffer to size*10 to allow bursts of tasks.
func NewWorkerPool(size int) *WorkerPool {
	wp := &WorkerPool{
		tasks: make(chan func(), size*10),
		size:  size,
	}
	for i := 0; i < size; i++ {
		go wp.worker()
	}
	return wp
}

func (wp *WorkerPool) worker() {
	for task := range wp.tasks {
		task()
		wp.wg.Done()
	}
}

// Submit adds a task to the pool and increments the waitgroup.
func (wp *WorkerPool) Submit(task func()) error {
	wp.wg.Add(1)
	wp.tasks <- task
	return nil
}

// Shutdown waits for all tasks to complete then closes the tasks channel.
func (wp *WorkerPool) Shutdown() {
	wp.wg.Wait()
	close(wp.tasks)
}

// RateLimiter implements a token bucket rate limiter.
type RateLimiter struct {
	tokens         int
	maxTokens      int
	mu             sync.Mutex
	refillInterval time.Duration
	quit           chan struct{}
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(maxTokens int, refillInterval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		tokens:         maxTokens,
		maxTokens:      maxTokens,
		refillInterval: refillInterval,
		quit:           make(chan struct{}),
	}
	go rl.refillTokens()
	return rl
}

func (rl *RateLimiter) refillTokens() {
	ticker := time.NewTicker(rl.refillInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			rl.tokens = rl.maxTokens
			rl.mu.Unlock()
		case <-rl.quit:
			return
		}
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

func (rl *RateLimiter) Stop() {
	close(rl.quit)
}

// Group represents a set of routes with a common prefix and its own middleware.
type Group struct {
	prefix      string
	middlewares []Middleware
	router      *Router
}

// Group creates a new route group with the given prefix and optional middlewares.
func (r *Router) Group(prefix string, middlewares ...Middleware) *Group {
	return &Group{
		prefix:      prefix,
		middlewares: middlewares,
		router:      r,
	}
}

// Group allows for nested groups by appending the new prefix and middlewares.
func (g *Group) Group(prefix string, middlewares ...Middleware) *Group {
	newPrefix := g.prefix + prefix
	newMiddlewares := append(g.middlewares, middlewares...)
	return &Group{
		prefix:      newPrefix,
		middlewares: newMiddlewares,
		router:      g.router,
	}
}

// applyMiddlewares wraps the given handler with the group's middleware chain.
func (g *Group) applyMiddlewares(handler http.HandlerFunc) http.HandlerFunc {
	final := handler
	// Apply group middlewares in reverse order so they run in registration order.
	for i := len(g.middlewares) - 1; i >= 0; i-- {
		final = g.middlewares[i](final)
	}
	return final
}

// Handle registers a new route for the group.
func (g *Group) Handle(method, pattern string, handler http.HandlerFunc) *Group {
	fullPattern := g.prefix + pattern
	wrappedHandler := g.applyMiddlewares(handler)
	g.router.Handle(method, fullPattern, wrappedHandler)
	return g
}

// HandleFunc registers a new Context-based route for the group.
func (g *Group) HandleFunc(method, pattern string, handler func(*Context)) *Group {
	fullPattern := g.prefix + pattern
	wrappedHandler := g.applyMiddlewares(func(w http.ResponseWriter, r *http.Request) {
		ctx := &Context{Writer: w, Request: r}
		handler(ctx)
	})
	g.router.Handle(method, fullPattern, wrappedHandler)
	return g
}

// Convenience methods for common HTTP verbs.
func (g *Group) GET(pattern string, handler func(*Context)) *Group {
	return g.HandleFunc("GET", pattern, handler)
}

func (g *Group) POST(pattern string, handler func(*Context)) *Group {
	return g.HandleFunc("POST", pattern, handler)
}

func (g *Group) PUT(pattern string, handler func(*Context)) *Group {
	return g.HandleFunc("PUT", pattern, handler)
}

func (g *Group) DELETE(pattern string, handler func(*Context)) *Group {
	return g.HandleFunc("DELETE", pattern, handler)
}
