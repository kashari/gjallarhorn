package gjallarhorn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ====== Context Tests ======

func TestContextParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	params := map[string]string{"id": "42"}
	ctx := context.WithValue(req.Context(), ctxKey("params"), params)
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: req.WithContext(ctx)}

	if got := c.Param("id"); got != "42" {
		t.Errorf("Expected param '42', got %s", got)
	}
}

func TestContextParamInt(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	params := map[string]string{"num": "123"}
	ctx := context.WithValue(req.Context(), ctxKey("params"), params)
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: req.WithContext(ctx)}

	i, err := c.ParamInt("num")
	if err != nil || i != 123 {
		t.Errorf("Expected 123, got %d (err: %v)", i, err)
	}

	// Test with non-integer
	params["num"] = "abc"
	ctx = context.WithValue(req.Context(), ctxKey("params"), params)
	c.Request = req.WithContext(ctx)
	if _, err := c.ParamInt("num"); err == nil {
		t.Errorf("Expected error for non-integer conversion")
	}
}

func TestContextParamInt64(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	params := map[string]string{"num": "4567890123"}
	ctx := context.WithValue(req.Context(), ctxKey("params"), params)
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: req.WithContext(ctx)}

	i, err := c.ParamInt64("num")
	if err != nil || i != 4567890123 {
		t.Errorf("Expected 4567890123, got %d (err: %v)", i, err)
	}
}

func TestContextParamFloat64(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	params := map[string]string{"pi": "3.14"}
	ctx := context.WithValue(req.Context(), ctxKey("params"), params)
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: req.WithContext(ctx)}

	f, err := c.ParamFloat64("pi")
	if err != nil || f != 3.14 {
		t.Errorf("Expected 3.14, got %f (err: %v)", f, err)
	}
}

func TestContextParamBool(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	params := map[string]string{"active": "true"}
	ctx := context.WithValue(req.Context(), ctxKey("params"), params)
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: req.WithContext(ctx)}

	b, err := c.ParamBool("active")
	if err != nil || b != true {
		t.Errorf("Expected true, got %v (err: %v)", b, err)
	}
}

func TestContextQuery(t *testing.T) {
	req := httptest.NewRequest("GET", "/?foo=bar&baz=qux", nil)
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: req}

	q := c.Query()
	if q["foo"] != "bar" || q["baz"] != "qux" {
		t.Errorf("Expected query parameters not returned correctly, got %v", q)
	}
}

func TestContextQueryParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/?name=gjallarhorn", nil)
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: req}

	if c.QueryParam("name") != "gjallarhorn" {
		t.Errorf("Expected 'gjallarhorn', got %s", c.QueryParam("name"))
	}
}

func TestContextBody(t *testing.T) {
	data := []byte("Hello, World!")
	req := httptest.NewRequest("POST", "/test", bytes.NewBuffer(data))
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: req}

	body := c.Body()
	if string(body) != "Hello, World!" {
		t.Errorf("Expected body to be 'Hello, World!', got %s", string(body))
	}
}

func TestContextJsonBody(t *testing.T) {
	jsonData := `{"key": "value", "num": 10}`
	req := httptest.NewRequest("POST", "/test", bytes.NewBufferString(jsonData))
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: req}

	body := c.JsonBody()
	if body["key"] != "value" || int(body["num"].(float64)) != 10 {
		t.Errorf("Expected map with key 'value' and num 10, got %v", body)
	}
}

func TestContextBindJSON(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	jsonData := `{"name": "Alice", "age": 30}`
	req := httptest.NewRequest("POST", "/test", bytes.NewBufferString(jsonData))
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: req}

	var p payload
	if err := c.BindJSON(&p); err != nil {
		t.Errorf("BindJSON returned error: %v", err)
	}
	if p.Name != "Alice" || p.Age != 30 {
		t.Errorf("Expected Alice/30, got %v", p)
	}
}

func TestContextJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: httptest.NewRequest("GET", "/test", nil)}

	data := map[string]interface{}{"status": "ok"}
	c.JSON(http.StatusAccepted, data)

	if rec.Code != http.StatusAccepted {
		t.Errorf("Expected status %d, got %d", http.StatusAccepted, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", ct)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Errorf("Error decoding response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("Expected JSON key status to be 'ok', got %v", resp["status"])
	}
}

func TestContextString(t *testing.T) {
	rec := httptest.NewRecorder()
	c := &Context{Writer: rec, Request: httptest.NewRequest("GET", "/test", nil)}

	c.String(http.StatusOK, "plain text")
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Expected Content-Type text/plain, got %s", ct)
	}
	if rec.Body.String() != "plain text" {
		t.Errorf("Expected body 'plain text', got %s", rec.Body.String())
	}
}

// ====== Router and Route Registration Tests ======

func TestStaticRouteRegistration(t *testing.T) {
	r := Heimdallr()
	r.Handle("GET", "/static", func(w http.ResponseWriter, req *http.Request) {})
	routes := r.ListRoutes()
	found := false
	for _, route := range routes {
		if strings.Contains(route, "GET /static") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Static route not registered correctly")
	}
}

func TestDynamicRouteRegistration(t *testing.T) {
	r := Heimdallr()
	r.Handle("GET", "/user/:id", func(w http.ResponseWriter, req *http.Request) {})
	routes := r.ListRoutes()
	found := false
	for _, route := range routes {
		if strings.Contains(route, "GET /user/:id") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Dynamic route not registered correctly")
	}
}

func TestListRoutes(t *testing.T) {
	r := Heimdallr()
	r.Handle("GET", "/a", func(w http.ResponseWriter, req *http.Request) {})
	r.Handle("POST", "/b/:id", func(w http.ResponseWriter, req *http.Request) {})
	routes := r.ListRoutes()
	if len(routes) != 2 {
		t.Errorf("Expected 2 routes, got %d", len(routes))
	}
}

// ====== ServeHTTP and Routing Tests ======

func TestServeHTTPStaticRoute(t *testing.T) {
	r := Heimdallr()
	expected := "static response"
	r.Handle("GET", "/static", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(expected))
	})
	req := httptest.NewRequest("GET", "/static", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Body.String() != expected {
		t.Errorf("Expected response '%s', got '%s'", expected, rec.Body.String())
	}
}

func TestServeHTTPDynamicRoute(t *testing.T) {
	r := Heimdallr()
	var receivedID string
	r.Handle("GET", "/user/:id", func(w http.ResponseWriter, req *http.Request) {
		c := &Context{Writer: w, Request: req}
		receivedID = c.Param("id")
		w.Write([]byte(receivedID))
	})
	req := httptest.NewRequest("GET", "/user/12345", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if receivedID != "12345" {
		t.Errorf("Expected dynamic param '12345', got '%s'", receivedID)
	}
}

func TestServeHTTPNotFound(t *testing.T) {
	r := Heimdallr()
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected 404 Not Found, got %d", rec.Code)
	}
}

func TestServeHTTPMethodNotAllowed(t *testing.T) {
	r := Heimdallr()
	r.Handle("GET", "/test", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("OK"))
	})
	req := httptest.NewRequest("POST", "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 Method Not Allowed, got %d", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET" {
		t.Errorf("Expected Allow header to be 'GET', got '%s'", allow)
	}
}

// ====== Middleware and Execution Tests ======

func TestMiddlewareChain(t *testing.T) {
	var callOrder []string

	mw1 := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			callOrder = append(callOrder, "mw1-before")
			next(w, req)
			callOrder = append(callOrder, "mw1-after")
		}
	}
	mw2 := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			callOrder = append(callOrder, "mw2-before")
			next(w, req)
			callOrder = append(callOrder, "mw2-after")
		}
	}
	r := Heimdallr()
	r.Use(mw1).Use(mw2)
	r.Handle("GET", "/test", func(w http.ResponseWriter, req *http.Request) {
		callOrder = append(callOrder, "handler")
	})
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	expectedOrder := []string{"mw1-before", "mw2-before", "handler", "mw2-after", "mw1-after"}
	if !equalSlices(callOrder, expectedOrder) {
		t.Errorf("Expected call order %v, got %v", expectedOrder, callOrder)
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, s := range a {
		if s != b[i] {
			return false
		}
	}
	return true
}

// ====== RateLimiter Tests ======

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(2, time.Second)
	if !rl.Allow() {
		t.Error("Expected first Allow() to succeed")
	}
	if !rl.Allow() {
		t.Error("Expected second Allow() to succeed")
	}
	if rl.Allow() {
		t.Error("Expected third Allow() to fail due to token exhaustion")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	rl := NewRateLimiter(1, 100*time.Millisecond)
	if !rl.Allow() {
		t.Error("Expected Allow() to succeed")
	}
	if rl.Allow() {
		t.Error("Expected Allow() to fail after token used")
	}
	time.Sleep(150 * time.Millisecond)
	if !rl.Allow() {
		t.Error("Expected Allow() to succeed after refill")
	}
	rl.Stop()
}

func TestRateLimiterStop(t *testing.T) {
	rl := NewRateLimiter(1, 100*time.Millisecond)
	rl.Stop()
	if rl.Allow() {
		// token was available initially.
	} else {
		t.Error("Expected Allow() to succeed initially")
	}
	if rl.Allow() {
		t.Error("Expected Allow() to fail after token is consumed and no refill after Stop()")
	}
}

// ====== WorkerPool Tests ======

func TestWorkerPoolSubmitAndShutdown(t *testing.T) {
	wp := NewWorkerPool(3)
	var mu sync.Mutex
	counter := 0
	task := func() {
		mu.Lock()
		counter++
		mu.Unlock()
	}
	for i := 0; i < 5; i++ {
		wp.Submit(task)
	}
	wp.Shutdown()
	if counter != 5 {
		t.Errorf("Expected counter to be 5, got %d", counter)
	}
}

func TestWithWorkerPool(t *testing.T) {
	r := Heimdallr().WithWorkerPool(2)
	done := false
	r.Handle("GET", "/wp", func(w http.ResponseWriter, req *http.Request) {
		done = true
		w.Write([]byte("done"))
	})
	req := httptest.NewRequest("GET", "/wp", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if !done {
		t.Error("Expected handler to execute using worker pool")
	}
}

// ====== Router RateLimiter Integration Test ======

func TestWithRateLimiter(t *testing.T) {
	r := Heimdallr().WithRateLimiter(1, time.Second)
	r.Handle("GET", "/rl", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("ok"))
	})
	req1 := httptest.NewRequest("GET", "/rl", nil)
	rec1 := httptest.NewRecorder()
	r.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", rec1.Code)
	}
	req2 := httptest.NewRequest("GET", "/rl", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 Too Many Requests, got %d", rec2.Code)
	}
}

// ====== File Logging Test ======

func TestWithFileLogging(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "logtest")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	r := Heimdallr().WithFileLogging(tmpFile.Name())
	r.Info("test log entry")
	time.Sleep(50 * time.Millisecond)
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read temp file: %v", err)
	}
	if !strings.Contains(string(content), "test log entry") {
		t.Errorf("Expected log entry to be written to file, got: %s", string(content))
	}
}

// ====== HandleFunc and HTTP Method Helpers Tests ======

func TestHandleFunc(t *testing.T) {
	called := false
	r := Heimdallr()
	r.HandleFunc("GET", "/handlefunc", func(c *Context) {
		called = true
		c.String(200, "handled")
	})
	req := httptest.NewRequest("GET", "/handlefunc", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if !called {
		t.Error("Expected HandleFunc route to be executed")
	}
	if rec.Body.String() != "handled" {
		t.Errorf("Expected body 'handled', got '%s'", rec.Body.String())
	}
}

func TestHTTPMethods(t *testing.T) {
	r := Heimdallr()
	r.GET("/get", func(c *Context) { c.String(200, "GET") })
	r.POST("/post", func(c *Context) { c.String(200, "POST") })
	r.PUT("/put", func(c *Context) { c.String(200, "PUT") })
	r.DELETE("/delete", func(c *Context) { c.String(200, "DELETE") })

	routes := r.ListRoutes()
	methods := []string{"GET /get", "POST /post", "PUT /put", "DELETE /delete"}
	for _, m := range methods {
		found := false
		for _, route := range routes {
			if strings.Contains(route, m) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected route %s to be registered", m)
		}
	}
}

// ====== Utility Function Tests ======

func TestMatchPattern(t *testing.T) {
	params, ok := matchPattern("/user/:id", "/user/789")
	if !ok || params["id"] != "789" {
		t.Errorf("Expected match with id=789, got %v (ok=%v)", params, ok)
	}
	_, ok = matchPattern("/user/:id", "/admin/789")
	if ok {
		t.Error("Expected no match for differing static parts")
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"/a/b/c", []string{"a", "b", "c"}},
		{"/", []string{}},
		{"//a//b//", []string{"a", "b"}},
	}
	for _, tc := range tests {
		got := splitPath(tc.input)
		if !equalSlices(got, tc.expected) {
			t.Errorf("For input %q, expected %v, got %v", tc.input, tc.expected, got)
		}
	}
}

func TestGetFunctionName(t *testing.T) {
	fn := func() {}
	name := getFunctionName(fn)
	if name == "" {
		t.Error("Expected a non-empty function name")
	}
}

func TestWorkerPoolConcurrency(t *testing.T) {
	wp := NewWorkerPool(5)
	var mu sync.Mutex
	counter := 0
	start := time.Now()
	task := func() {
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		counter++
		mu.Unlock()
	}
	for i := 0; i < 10; i++ {
		wp.Submit(task)
	}
	wp.Shutdown()
	elapsed := time.Since(start)
	if elapsed > 300*time.Millisecond {
		t.Errorf("Expected tasks to run concurrently; took too long: %s", elapsed)
	}
	if counter != 10 {
		t.Errorf("Expected 10 tasks executed, got %d", counter)
	}
}

func TestGroupGET(t *testing.T) {
	// Create a new router.
	r := Heimdallr()

	// Define a simple middleware that adds a header.
	testMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("X-Test-Middleware", "applied")
			next(w, req)
		}
	}

	// Create a group with prefix "/api" and attach the middleware.
	group := r.Group("/api", testMiddleware)
	group.GET("/test", func(c *Context) {
		c.String(http.StatusOK, "group GET test")
	})

	// Create a request to the full path "/api/test".
	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check that the middleware header is present.
	if headerVal := resp.Header.Get("X-Test-Middleware"); headerVal != "applied" {
		t.Errorf("Expected middleware header to be 'applied', got '%s'", headerVal)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "group GET test" {
		t.Errorf("Unexpected response body: %s", string(body))
	}
}

// TestNestedGroup verifies that nested groups combine their prefixes and middlewares.
func TestNestedGroup(t *testing.T) {
	r := Heimdallr()

	// Parent middleware adds a header.
	parentMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			w.Header().Add("X-Parent", "parent")
			next(w, req)
		}
	}

	// Child middleware adds a different header.
	childMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			w.Header().Add("X-Child", "child")
			next(w, req)
		}
	}

	// Create a parent group with prefix "/api" and attach the parent middleware.
	group := r.Group("/api", parentMiddleware)
	// Create a nested group with prefix "/admin" and attach the child middleware.
	nestedGroup := group.Group("/admin", childMiddleware)
	nestedGroup.GET("/dashboard", func(c *Context) {
		c.String(http.StatusOK, "nested group test")
	})

	// Send a GET request to the combined route "/api/admin/dashboard".
	req := httptest.NewRequest("GET", "/api/admin/dashboard", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify that both middlewares have been applied.
	if resp.Header.Get("X-Parent") != "parent" {
		t.Errorf("Expected header X-Parent to be 'parent', got '%s'", resp.Header.Get("X-Parent"))
	}
	if resp.Header.Get("X-Child") != "child" {
		t.Errorf("Expected header X-Child to be 'child', got '%s'", resp.Header.Get("X-Child"))
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "nested group test" {
		t.Errorf("Unexpected response body: %s", string(body))
	}
}

// TestGroupListRoutes verifies that routes registered via groups appear in the router’s list.
func TestGroupListRoutes(t *testing.T) {
	r := Heimdallr()
	group := r.Group("/api")
	group.GET("/users", func(c *Context) {
		c.String(http.StatusOK, "users list")
	})

	routes := r.ListRoutes()
	expectedRoute := "GET /api/users"
	found := false
	for _, rt := range routes {
		if rt == expectedRoute {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected route '%s' to be registered, got routes: %v", expectedRoute, routes)
	}
}

func TestRouterStress(t *testing.T) {
	// Create a new router instance and add a stress endpoint.
	router := Heimdallr()
	router.GET("/stress", func(c *Context) {
		// Simulate CPU-bound work.
		sum := 0
		for i := 0; i < 100000; i++ {
			sum += i
		}
		// Simulate I/O delay.
		time.Sleep(5 * time.Millisecond)
		c.String(http.StatusOK, fmt.Sprintf("OK %d", sum))
	})

	// Use httptest server to run the router.
	ts := httptest.NewServer(router)
	defer ts.Close()

	var wg sync.WaitGroup
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Stress test parameters.
	totalRequests := 5000 // Total number of requests to issue.
	concurrency := 200    // Maximum number of concurrent requests.
	sem := make(chan struct{}, concurrency)

	startTime := time.Now()
	var errorCount int
	var mu sync.Mutex

	// Issue totalRequests concurrently.
	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore slot

		go func(reqID int) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore slot

			resp, err := client.Get(ts.URL + "/stress")
			if err != nil {
				mu.Lock()
				errorCount++
				mu.Unlock()
				t.Errorf("Request %d failed: %v", reqID, err)
				return
			}
			if resp.StatusCode != http.StatusOK {
				mu.Lock()
				errorCount++
				mu.Unlock()
				t.Errorf("Request %d got status %d", reqID, resp.StatusCode)
			}
			// Drain and close the response body.
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(startTime)
	t.Logf("Stress test completed: %d requests in %s, errors: %d", totalRequests, elapsed, errorCount)

	// You can define thresholds for acceptable performance.
	if elapsed > 10*time.Second {
		t.Errorf("Stress test took too long: %s", elapsed)
	}
}
