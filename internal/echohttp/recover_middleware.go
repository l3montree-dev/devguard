package echohttp

import (
	"fmt"
	"net/http"
	"runtime"

	"github.com/labstack/echo/v4"
)

func recovermiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) (returnErr error) {
			defer func() {
				if r := recover(); r != nil {
					if r == http.ErrAbortHandler {
						panic(r)
					}
					err, ok := r.(error)
					if !ok {
						err = fmt.Errorf("%v", r)
					}
					var stack []byte
					var length int

					stack = make([]byte, 4<<10) // 4 KB
					length = runtime.Stack(stack, false)

					fmt.Println(err, string(stack[:length]))

					// Log the error and stack trace for debugging
					fmt.Println("Recovered from panic:", err)
					fmt.Println("Stack trace:", string(stack[:length]))
				}
			}()
			return next(ctx)
		}
	}
}
