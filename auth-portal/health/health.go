package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type Checker func(ctx context.Context) error

type Result struct {
	Status string            `json:"status"` // "ok" or "degraded" or "fail"
	Checks map[string]string `json:"checks"`
}

func LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Result{
			Status: "ok",
			Checks: map[string]string{"process": "ok"},
		})
	}
}

func ReadinessHandler(checks map[string]Checker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		res := Result{Status: "ok", Checks: map[string]string{}}
		for name, fn := range checks {
			if err := fn(ctx); err != nil {
				res.Checks[name] = "fail: " + err.Error()
				if res.Status == "ok" {
					res.Status = "fail"
				}
			} else {
				res.Checks[name] = "ok"
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if res.Status == "ok" {
			w.WriteHeader(http.StatusOK)
		} else {
			// If any dependency fails, readiness should be non-200 so K8s stops routing
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(res)
	}
}