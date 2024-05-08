package sbi

import (
	"github.com/gin-gonic/gin"
)
type RouteGroup interface {
	AddService(engine *gin.Engine) *gin.RouterGroup
}

// Routes is the list of the generated Route.
type Routes []Route

// NewRouter returns a new router.
func NewRouter() *gin.Engine {
	router := logger_util.NewGinWithLogrus(logger.GinLog)
	AddService(router)
	return router
}

func authorizationCheck(c *gin.Context) error {
	token := c.Request.Header.Get("Authorization")
	return nrf_context.GetSelf().AuthorizationCheck(token, "nnrf-disc")
}

func AddService(group *gin.RouterGroup, routes []Route) {
	for _, route := range routes {
		switch route.Method {
		case "GET":
			group.GET(route.Pattern, route.HandlerFunc)
		case "POST":
			group.POST(route.Pattern, route.HandlerFunc)
		case "PUT":
			group.PUT(route.Pattern, route.HandlerFunc)
		case "DELETE":
			group.DELETE(route.Pattern, route.HandlerFunc)
		case "PATCH":
			group.PATCH(route.Pattern, route.HandlerFunc)
		}
	}
}