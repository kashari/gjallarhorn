# Gjallarhorn

Gjallarhorn is a lightweight, flexible HTTP router for Go. It supports static and dynamic routing, middleware chaining, a worker pool for concurrent request handling, token bucket rate limiting, and file logging—all built to simplify web application development.

## Features

- **Static and Dynamic Routing:** Easily register routes with fixed paths or dynamic parameters (e.g., `/user/:id`).
- **Middleware Support:** Chain middleware functions to handle authentication, logging, error handling, and more.
- **Worker Pool:** Offload request handling to a pool of goroutines for improved performance under load.
- **Rate Limiter:** Protect your application with a built-in token bucket rate limiter.
- **File Logging:** Log output to a file in addition to the console.
- **Context Utilities:** Convenient methods for parsing URL parameters, query strings, JSON bodies, and sending responses.

## Installation

Install Gjallarhorn using `go get`:

```bash
go get github.com/kashari/gjallarhorn
```

## Quick Start
Below is a simple example to demonstrate how to create a router, add middleware, register routes, and start an HTTP server:

```go
package main

import (
    "net/http"
    "time"

    "github.com/yourusername/gjallarhorn"
)

func main() {
    // Create a new router instance.
    router := gjallarhorn.Heimdallr()

    // Add a simple logging middleware.
    router.Use(func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, req *http.Request) {
            println("Incoming request:", req.Method, req.URL.Path)
            next(w, req)
        }
    })

    // Optionally configure rate limiter and worker pool.
    router.WithRateLimiter(10, time.Second)
    router.WithWorkerPool(5)

    // Register routes.
    router.GET("/hello", func(c *gjallarhorn.Context) {
        c.String(http.StatusOK, "Hello, Gjallarhorn!")
    })

    router.GET("/user/:id", func(c *gjallarhorn.Context) {
        userID := c.Param("id")
        c.JSON(http.StatusOK, map[string]string{"user_id": userID})
    })

    // Optionally enable file logging.
    router.WithFileLogging("server.log")

    // Start the server.
    if err := router.Start("8080"); err != nil {
        panic(err)
    }
}
```

## API Documentation

### Creating a Router
`Heimdallr() *Router`

- Creates and returns a new router instance with default settings, including an empty middleware chain and route registry.

### Route Registration

- GET(pattern string, handler func(*Context)) *Router
- POST(pattern string, handler func(*Context)) *Router
- PUT(pattern string, handler func(*Context)) *Router
- DELETE(pattern string, handler func(*Context)) *Router


These helper methods register routes for their respective HTTP methods.

### Middleware
Use
`(m Middleware) *Router`

- Adds a middleware function to the router. Middleware functions wrap the execution of route handlers, allowing you to perform actions before and after the handler runs.

### Worker Pool and Rate Limiter
`WithWorkerPool(poolSize int) *Router`
- Configures the router to use a worker pool of the given size, enabling concurrent processing of requests.

`WithRateLimiter(maxTokens int, refillInterval time.Duration) *Router`

- Sets up a token bucket rate limiter that limits the number of requests processed in a given interval.

## Example 
Adding a JWT Token auth requirement middleware to the routes.
```go

package main

import (
    "net/http"
    "strings"

    "github.com/golang-jwt/jwt/v5"
    "github.com/yourusername/gjallarhorn"
)

var secretKey = []byte("your_secret_key")

auth := func (next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, req *http.Request) {
        authHeader := req.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Missing Authorization Header", http.StatusUnauthorized)
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, jwt.ErrSignatureInvalid
            }
            return secretKey, nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid Token", http.StatusUnauthorized)
            return
        }

        next(w, req)
    }
}

r := gjallarhorn.Heimdallr()

// public route
r.GET("/public", func(c *gjallarhorn.Context) {
    c.String(http.StatusOK, "This is a public route")
})

r.Use(auth)

// Protected route (wrapped with JWTAuthMiddleware)
r.GET("/protected", func(c *gjallarhorn.Context) {
    c.String(http.StatusOK, "This is a protected route")
})
```

### Or, better yet, group the auth needing routes

```go
group := r.Group("/api", auth) // directly attach the middleware
group.GET("/protected", func(c *gjallarhorn.Context) {
    c.String(http.StatusOK, "This is a protected route, will give 401 if not authenticated...")
})
```

This will give the user 401 only on the prefixed routes!

## Example of a real world app main package
```go
package main

import (
	"log"
	"net/http"
	"gjallarhorn"
)

func helloHandler(c *gjallarhorn.Context) {
	c.String(http.StatusOK, "Hello, world!")
}

func getUsers(c *gjallarhorn.Context) {
	users := []string{"Alice", "Bob", "Charlie"}
	c.JSON(http.StatusOK, users)
}

func createUser(c *gjallarhorn.Context) {
	c.String(http.StatusCreated, "User created")
}

func adminDashboard(c *gjallarhorn.Context) {
	c.String(http.StatusOK, "Welcome to the admin dashboard")
}

func main() {
	// Initialize the router.
	router := gjallarhorn.Heimdallr()

	// Register a normal route.
	router.GET("/hello", helloHandler)

	// Create a group for API routes with a logging middleware.
	apiGroup := router.Group("/api", loggingMiddleware)
	apiGroup.GET("/users", getUsers)
	apiGroup.POST("/users", createUser)

	// Create a nested group under /api/admin with additional admin middleware.
	adminGroup := apiGroup.Group("/admin", adminMiddleware)
	adminGroup.GET("/dashboard", adminDashboard)

	// Start the server on port 8080.
	port := "8080"
	log.Printf("Server starting on port %s", port)
	if err := router.Start(port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
```


## Contributing
Contributions are welcome! If you have suggestions, bug fixes, or enhancements, please open an issue or submit a pull request.