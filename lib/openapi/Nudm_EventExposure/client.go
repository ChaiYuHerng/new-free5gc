/*
 * Nudm_EE
 *
 * Nudm Event Exposure Service
 *
 * API version: 1.0.1
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package Nudm_EventExposure

import (
	"crypto/tls"
	"net/http"

	"golang.org/x/net/http2"
)

// APIClient manages communication with the Nudm_EE API v1.0.1
// In most cases there should be only one, shared, APIClient.
type APIClient struct {
	cfg    *Configuration
	common service // Reuse a single struct instead of allocating one for each service on the heap.

	// API Services
	CreateEESubscriptionApi *CreateEESubscriptionApiService
	DeleteEESubscriptionApi *DeleteEESubscriptionApiService
	UpdateEESubscriptionApi *UpdateEESubscriptionApiService
}

type service struct {
	client *APIClient
}

// NewAPIClient creates a new API client. Requires a userAgent string describing your application.
// optionally a custom http.Client to allow for advanced features such as caching.
func NewAPIClient(cfg *Configuration) *APIClient {
	if cfg.httpClient == nil {
		cfg.httpClient = http.DefaultClient
		cfg.httpClient.Transport = &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	c := &APIClient{}
	c.cfg = cfg
	c.common.client = c

	// API Services
	c.CreateEESubscriptionApi = (*CreateEESubscriptionApiService)(&c.common)
	c.DeleteEESubscriptionApi = (*DeleteEESubscriptionApiService)(&c.common)
	c.UpdateEESubscriptionApi = (*UpdateEESubscriptionApiService)(&c.common)

	return c
}
