package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Route struct {
	Method  string
	Pattern string
	APIFunc gin.HandlerFunc
}

func applyRoutes(group *gin.RouterGroup, routes []Route) {
	for _, route := range routes {
		switch route.Method {
		case http.MethodGet:
			group.GET(route.Pattern, route.APIFunc)
		case http.MethodPost:
			group.POST(route.Pattern, route.APIFunc)
		case http.MethodPut:
			group.PUT(route.Pattern, route.APIFunc)
		case http.MethodPatch:
			group.PATCH(route.Pattern, route.APIFunc)
		case http.MethodDelete:
			group.DELETE(route.Pattern, route.APIFunc)
		}
	}
}
