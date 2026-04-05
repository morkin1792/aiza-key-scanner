// aiza-key-scanner — GCP API Key Validator
//
// Validates leaked GCP API Keys (AIzaSy...) and determines which Google APIs
// a key can access, collecting non-destructive PoC data to demonstrate impact.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// ─── Types ───────────────────────────────────────────────────────────────────

type Status int

const (
	StatusVulnerable Status = iota
	StatusForbidden
	StatusInvalid
	StatusError
)

func (s Status) String() string {
	switch s {
	case StatusVulnerable:
		return "vulnerable"
	case StatusForbidden:
		return "forbidden"
	case StatusInvalid:
		return "invalid"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

type ServiceCheck struct {
	Name         string
	Category     string
	NeedsProject bool
	// Run receives the URL-encoded key (already passed through url.QueryEscape).
	// Do NOT call url.QueryEscape again inside check functions.
	Run func(key, projectID string) CheckResult
}

type CheckResult struct {
	Service  string `json:"service"`
	Category string `json:"category"`
	Status   Status `json:"-"`
	StatusS  string `json:"status"`
	Detail   string `json:"detail"`
	RawJSON  string `json:"raw_json,omitempty"`
}

type KeyResult struct {
	Key       string        `json:"key"`
	ProjectID string        `json:"project_id"`
	Timestamp string        `json:"timestamp"`
	Results   []CheckResult `json:"results"`
}

// ─── Globals ─────────────────────────────────────────────────────────────────

var (
	client     *http.Client
	verbose    bool
	silent     int // 0=normal, 1=summary-only, 2=no output
	printMu    sync.Mutex
	keyPattern = regexp.MustCompile(`^AIzaSy[A-Za-z0-9_-]{33}$`)
	colorVuln  = color.New(color.FgRed, color.Bold)
	colorForb  = color.New(color.FgYellow)
	colorInv   = color.New(color.FgMagenta)
	colorErr   = color.New(color.FgCyan)
)

// ─── HTTP helpers ────────────────────────────────────────────────────────────

func doGet(url string) (int, []byte, error) {
	return doRequest("GET", url, nil)
}

func doPost(url string, body interface{}) (int, []byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	return doRequest("POST", url, data)
}

func doRequest(method, url string, body []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "aiza-key-scanner/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	// Retry once on 429
	if resp.StatusCode == 429 {
		time.Sleep(2 * time.Second)
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}
		ctx2, cancel2 := context.WithTimeout(context.Background(), client.Timeout)
		req2, err2 := http.NewRequestWithContext(ctx2, method, url, bodyReader)
		if err2 != nil {
			cancel2()
			return 429, respBody, nil
		}
		req2.Header.Set("User-Agent", "aiza-key-scanner/1.0")
		if body != nil {
			req2.Header.Set("Content-Type", "application/json")
		}
		resp2, err2 := client.Do(req2)
		cancel2()
		if err2 != nil {
			return 429, respBody, nil
		}
		defer resp2.Body.Close()
		respBody2, err2 := io.ReadAll(resp2.Body)
		if err2 != nil {
			return resp2.StatusCode, nil, err2
		}
		return resp2.StatusCode, respBody2, nil
	}

	return resp.StatusCode, respBody, nil
}

func rawIf(data []byte) string {
	if verbose {
		return string(data)
	}
	return ""
}

// unmarshal logs a warning to stderr in verbose mode if JSON decoding fails.
func unmarshal(body []byte, v interface{}) error {
	err := json.Unmarshal(body, v)
	if err != nil && verbose {
		fmt.Fprintf(os.Stderr, "[WARN] JSON decode error: %v (body prefix: %.120s)\n", err, body)
	}
	return err
}

// ─── Gateway logic ───────────────────────────────────────────────────────────

type gatewayResult struct {
	status    string // "ok", "forbidden", "invalid", "error"
	projectID string
	errMsg    string
	// Resource Manager result (populated on 200/403 so check4_1 is not needed)
	rmResult *CheckResult
}

func gatewayCheck(key, fallbackProject string) gatewayResult {
	escKey := url.QueryEscape(key)
	u := "https://cloudresourcemanager.googleapis.com/v1/projects?key=" + escKey
	code, body, err := doGet(u)
	if err != nil {
		return gatewayResult{status: "error", errMsg: err.Error()}
	}
	switch {
	case code == 200:
		var resp struct {
			Projects []struct {
				ProjectID string `json:"projectId"`
			} `json:"projects"`
		}
		var rmDetail string
		if json.Unmarshal(body, &resp) == nil {
			n := len(resp.Projects)
			rmDetail = fmt.Sprintf("%d projects", n)
			if n > 0 {
				names := make([]string, 0, min(5, n))
				for i := 0; i < min(5, n); i++ {
					names = append(names, resp.Projects[i].ProjectID)
				}
				rmDetail += ": " + strings.Join(names, ", ")
			}
		} else {
			rmDetail = "API accessible (parse error)"
		}
		rmCR := cr("Cloud Resource Manager", "GCP", StatusVulnerable, rmDetail, body)
		gr := gatewayResult{status: "ok", rmResult: &rmCR}
		if len(resp.Projects) > 0 {
			gr.projectID = resp.Projects[0].ProjectID
		} else if fallbackProject != "" {
			gr.projectID = fallbackProject
		}
		return gr
	case code == 401 || code == 403:
		rmCR := cr("Cloud Resource Manager", "GCP", StatusForbidden, "Key valid, API not enabled", body)
		return gatewayResult{status: "forbidden", projectID: fallbackProject, rmResult: &rmCR}
	case code == 400:
		return gatewayResult{status: "invalid"}
	default:
		return gatewayResult{status: "error", errMsg: fmt.Sprintf("HTTP %d", code)}
	}
}

// ─── Service Check builders ──────────────────────────────────────────────────

func buildChecks() []ServiceCheck {
	return []ServiceCheck{
		// ── GCP Infrastructure (32) ──
		// check4_1 (Cloud Resource Manager) omitted — already covered by gateway check
		check4_2(),
		check4_3(),
		check4_4(),
		check4_5(),
		check4_6(),
		check4_7(),
		check4_8(),
		check4_9(),
		check4_10(),
		check4_11(),
		check4_12(),
		check4_13(),
		check4_14(),
		check4_15(),
		check4_16(),
		check4_17(),
		check4_18(),
		check4_19(),
		check4_20(),
		checkMemorystore(),
		checkFilestore(),
		checkVPCNetworks(),
		checkCloudEndpoints(),
		checkCloudWorkflows(),
		checkSourceRepos(),
		checkCloudKMS(),
		checkDataflow(),
		checkCloudRetail(),
		checkCloudComposer(),
		checkAlloyDB(),
		checkBatchAPI(),
		checkBillingAccounts(),
		// ── Firebase (8) ──
		check4_21(),
		check4_22(),
		check4_23(),
		check4_24(),
		check4_25(),
		checkFirebaseHosting(),
		checkFirebaseExtensions(),
		checkFirebaseTestLab(),
		// ── Google Maps & Geo (23) ──
		// NOTE: check4_36 (Custom Search) is category "Search", listed separately below
		check4_26(),
		check4_27(),
		check4_28(),
		check4_29(),
		check4_30(),
		check4_31(),
		check4_32(),
		check4_33(),
		check4_34(),
		check4_35(),
		checkPlacesAutocomplete(),
		checkPlacesDetails(),
		checkMapsTile(),
		checkEmbedAPI(),
		checkSolarAPI(),
		checkAirQuality(),
		checkAddressValidation(),
		checkRoutesAPI(),
		checkRouteMatrix(),
		checkPollenAPI(),
		checkFindPlace(),
		checkAerialView(),
		checkPlacesNew(),
		// ── Search (1) ──
		check4_36(),
		// ── AI & Machine Learning (16) ──
		check4_37(),
		check4_38(),
		check4_39(),
		check4_40(),
		check4_41(),
		check4_42(),
		check4_43(),
		check4_44(),
		check4_45(),
		check4_46(),
		checkGeminiFiles(),
		checkGeminiEmbeddings(),
		checkGeminiTunedModels(),
		checkVideoIntelligence(),
		checkDocumentAI(),
		checkVertexAIDatasets(),
		// ── Media & Content (8) ──
		check4_47(),
		check4_48(),
		check4_49(),
		check4_50(),
		check4_51(),
		check4_52(),
		check4_53(),
		check4_54(),
		// ── Identity & Security (6) ──
		check4_55(),
		check4_56(),
		check4_57(),
		check4_58(),
		check4_59(),
		checkFirebaseAppCheck(),
	}
}

// ─── GCP Infrastructure checks ──────────────────────────────────────────────

func check4_2() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Storage", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s&key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Storage", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Items []struct {
						Name string `json:"name"`
					} `json:"items"`
				}
				unmarshal(body, &resp)
				n := len(resp.Items)
				detail := fmt.Sprintf("%d buckets", n)
				if n > 0 {
					names := make([]string, 0, min(5, n))
					for i := 0; i < min(5, n); i++ {
						names = append(names, resp.Items[i].Name)
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Storage", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Storage", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Storage", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_3() ServiceCheck {
	return ServiceCheck{
		Name: "Compute Engine", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/aggregated/instances?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Compute Engine", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Items map[string]struct {
						Instances []struct {
							Name string `json:"name"`
							Zone string `json:"zone"`
						} `json:"instances"`
					} `json:"items"`
				}
				unmarshal(body, &resp)
				total := 0
				var instances []string
				for _, zone := range resp.Items {
					for _, inst := range zone.Instances {
						total++
						if len(instances) < 3 {
							instances = append(instances, inst.Name)
						}
					}
				}
				detail := fmt.Sprintf("%d instances", total)
				if len(instances) > 0 {
					detail += ": " + strings.Join(instances, ", ")
				}
				return cr("Compute Engine", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Compute Engine", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Compute Engine", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_4() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud SQL", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://www.googleapis.com/sql/v1beta4/projects/%s/instances?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud SQL", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Items []struct {
						Name            string `json:"name"`
						DatabaseVersion string `json:"databaseVersion"`
					} `json:"items"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, item := range resp.Items {
					parts = append(parts, item.Name+"("+item.DatabaseVersion+")")
				}
				detail := fmt.Sprintf("%d instances", len(resp.Items))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud SQL", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud SQL", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud SQL", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_5() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud DNS", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://dns.googleapis.com/dns/v1/projects/%s/managedZones?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud DNS", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					ManagedZones []struct {
						Name    string `json:"name"`
						DNSName string `json:"dnsName"`
					} `json:"managedZones"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, z := range resp.ManagedZones {
					parts = append(parts, z.Name+"("+z.DNSName+")")
				}
				detail := fmt.Sprintf("%d zones", len(resp.ManagedZones))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud DNS", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud DNS", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud DNS", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_6() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Functions", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			// Query both v1 (Gen 1) and v2 (Gen 2) endpoints sequentially.
			// This makes two HTTP calls in one goroutine — worst case 2× timeout.
			type cfn struct {
				Name string
				URL  string
			}
			var allFns []cfn
			var lastBody []byte
			var sawForbidden bool
			var errs []string

			// Gen 1
			u1 := fmt.Sprintf("https://cloudfunctions.googleapis.com/v1/projects/%s/locations/-/functions?key=%s", projectID, key)
			code1, body1, err1 := doGet(u1)
			if err1 == nil {
				if code1 == 200 {
					var resp struct {
						Functions []struct {
							Name         string `json:"name"`
							HTTPSTrigger struct {
								URL string `json:"url"`
							} `json:"httpsTrigger"`
						} `json:"functions"`
					}
					unmarshal(body1, &resp)
					for _, f := range resp.Functions {
						allFns = append(allFns, cfn{Name: shortName(f.Name), URL: f.HTTPSTrigger.URL})
					}
					lastBody = body1
				} else if code1 == 401 || code1 == 403 {
					sawForbidden = true
					lastBody = body1
				} else {
					errs = append(errs, fmt.Sprintf("v1: HTTP %d", code1))
				}
			} else {
				errs = append(errs, "v1: "+err1.Error())
			}

			// Gen 2
			u2 := fmt.Sprintf("https://cloudfunctions.googleapis.com/v2/projects/%s/locations/-/functions?key=%s", projectID, key)
			code2, body2, err2 := doGet(u2)
			if err2 == nil {
				if code2 == 200 {
					var resp struct {
						Functions []struct {
							Name          string `json:"name"`
							ServiceConfig struct {
								URI string `json:"uri"`
							} `json:"serviceConfig"`
						} `json:"functions"`
					}
					unmarshal(body2, &resp)
					for _, f := range resp.Functions {
						allFns = append(allFns, cfn{Name: shortName(f.Name), URL: f.ServiceConfig.URI})
					}
					lastBody = body2
				} else if code2 == 401 || code2 == 403 {
					sawForbidden = true
					if lastBody == nil {
						lastBody = body2
					}
				} else {
					errs = append(errs, fmt.Sprintf("v2: HTTP %d", code2))
				}
			} else {
				errs = append(errs, "v2: "+err2.Error())
			}

			if len(allFns) > 0 {
				var parts []string
				for _, f := range allFns {
					s := f.Name
					if f.URL != "" {
						s += " → " + f.URL
					}
					parts = append(parts, s)
				}
				detail := fmt.Sprintf("%d functions (v1+v2)", len(allFns))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Functions", "GCP", StatusVulnerable, detail, lastBody)
			}
			if sawForbidden {
				return cr("Cloud Functions", "GCP", StatusForbidden, "Key valid, API not enabled", lastBody)
			}
			if len(errs) > 0 {
				return cr("Cloud Functions", "GCP", StatusError, strings.Join(errs, "; "), lastBody)
			}
			return cr("Cloud Functions", "GCP", StatusError, "no response from v1 or v2", nil)
		},
	}
}

func check4_7() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Run", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://run.googleapis.com/v2/projects/%s/locations/-/services?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Run", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Services []struct {
						Name string `json:"name"`
						URI  string `json:"uri"`
					} `json:"services"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, s := range resp.Services {
					p := shortName(s.Name)
					if s.URI != "" {
						p += " → " + s.URI
					}
					parts = append(parts, p)
				}
				detail := fmt.Sprintf("%d services", len(resp.Services))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Run", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Run", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Run", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_8() ServiceCheck {
	return ServiceCheck{
		Name: "GKE", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/-/clusters?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("GKE", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Clusters []struct {
						Name           string `json:"name"`
						Location       string `json:"location"`
						CurrentNodeVersion string `json:"currentNodeVersion"`
					} `json:"clusters"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, c := range resp.Clusters {
					parts = append(parts, fmt.Sprintf("%s (%s, v%s)", c.Name, c.Location, c.CurrentNodeVersion))
				}
				detail := fmt.Sprintf("%d clusters", len(resp.Clusters))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("GKE", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("GKE", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("GKE", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_9() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Pub/Sub", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://pubsub.googleapis.com/v1/projects/%s/topics?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Pub/Sub", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Topics []struct {
						Name string `json:"name"`
					} `json:"topics"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, t := range resp.Topics {
					names = append(names, shortName(t.Name))
				}
				detail := fmt.Sprintf("%d topics", len(resp.Topics))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Pub/Sub", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Pub/Sub", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Pub/Sub", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_10() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Spanner", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://spanner.googleapis.com/v1/projects/%s/instances?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Spanner", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Instances []struct {
						Name   string `json:"name"`
						Config string `json:"config"`
					} `json:"instances"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, i := range resp.Instances {
					parts = append(parts, shortName(i.Name))
				}
				detail := fmt.Sprintf("%d instances", len(resp.Instances))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Spanner", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Spanner", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Spanner", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_11() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Bigtable", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://bigtableadmin.googleapis.com/v2/projects/%s/instances?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Bigtable", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Instances []struct {
						Name string `json:"name"`
					} `json:"instances"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, i := range resp.Instances {
					names = append(names, shortName(i.Name))
				}
				detail := fmt.Sprintf("%d instances", len(resp.Instances))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Bigtable", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Bigtable", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Bigtable", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_12() ServiceCheck {
	return ServiceCheck{
		Name: "Secret Manager", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Secret Manager", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Secrets []struct {
						Name string `json:"name"`
					} `json:"secrets"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, s := range resp.Secrets {
					names = append(names, shortName(s.Name))
				}
				detail := fmt.Sprintf("%d secrets", len(resp.Secrets))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Secret Manager", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Secret Manager", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Secret Manager", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_13() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Logging", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := "https://logging.googleapis.com/v2/entries:list?key=" + key
			payload := map[string]interface{}{
				"resourceNames": []string{"projects/" + projectID},
				"pageSize":      5,
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Cloud Logging", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Entries []struct {
						Timestamp string `json:"timestamp"`
					} `json:"entries"`
				}
				unmarshal(body, &resp)
				detail := "Log read access confirmed"
				if len(resp.Entries) > 0 {
					detail += ", most recent: " + resp.Entries[0].Timestamp
				}
				return cr("Cloud Logging", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Logging", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Logging", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_14() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Monitoring", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://monitoring.googleapis.com/v3/projects/%s/metricDescriptors?key=%s&pageSize=3", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Monitoring", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Cloud Monitoring", "GCP", StatusVulnerable, "Monitoring API access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Monitoring", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Monitoring", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_15() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Tasks", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://cloudtasks.googleapis.com/v2/projects/%s/locations/-/queues?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Tasks", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Queues []struct {
						Name string `json:"name"`
					} `json:"queues"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, q := range resp.Queues {
					names = append(names, shortName(q.Name))
				}
				detail := fmt.Sprintf("%d queues", len(resp.Queues))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Tasks", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Tasks", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Tasks", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_16() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Scheduler", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://cloudscheduler.googleapis.com/v1/projects/%s/locations/-/jobs?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Scheduler", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Jobs []struct {
						Name     string `json:"name"`
						Schedule string `json:"schedule"`
					} `json:"jobs"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, j := range resp.Jobs {
					parts = append(parts, shortName(j.Name)+"("+j.Schedule+")")
				}
				detail := fmt.Sprintf("%d jobs", len(resp.Jobs))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Scheduler", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Scheduler", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Scheduler", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_17() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Build", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://cloudbuild.googleapis.com/v1/projects/%s/builds?key=%s&pageSize=3", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Build", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Builds []struct {
						ID     string `json:"id"`
						Status string `json:"status"`
					} `json:"builds"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, b := range resp.Builds {
					parts = append(parts, b.ID[:min(8, len(b.ID))]+"("+b.Status+")")
				}
				detail := fmt.Sprintf("%d recent builds", len(resp.Builds))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Build", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Build", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Build", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_18() ServiceCheck {
	return ServiceCheck{
		Name: "Artifact Registry", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://artifactregistry.googleapis.com/v1/projects/%s/locations/-/repositories?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Artifact Registry", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Repositories []struct {
						Name   string `json:"name"`
						Format string `json:"format"`
					} `json:"repositories"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, r := range resp.Repositories {
					parts = append(parts, shortName(r.Name)+"("+r.Format+")")
				}
				detail := fmt.Sprintf("%d repositories", len(resp.Repositories))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Artifact Registry", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Artifact Registry", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Artifact Registry", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_19() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Firestore", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents?key=%s&pageSize=3", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Firestore", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Documents []struct {
						Name string `json:"name"`
					} `json:"documents"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, d := range resp.Documents {
					names = append(names, shortName(d.Name))
				}
				detail := fmt.Sprintf("%d top-level documents", len(resp.Documents))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Firestore", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Firestore", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Firestore", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_20() ServiceCheck {
	return ServiceCheck{
		Name: "BigQuery", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://bigquery.googleapis.com/bigquery/v2/projects/%s/datasets?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("BigQuery", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Datasets []struct {
						DatasetReference struct {
							DatasetID string `json:"datasetId"`
						} `json:"datasetReference"`
						Location string `json:"location"`
					} `json:"datasets"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, d := range resp.Datasets {
					parts = append(parts, d.DatasetReference.DatasetID+"("+d.Location+")")
				}
				detail := fmt.Sprintf("%d datasets", len(resp.Datasets))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("BigQuery", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("BigQuery", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("BigQuery", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

// ─── Firebase checks ─────────────────────────────────────────────────────────

func check4_21() ServiceCheck {
	return ServiceCheck{
		Name: "Firebase Auth Signup", Category: "Firebase", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + key
			payload := map[string]interface{}{"returnSecureToken": true}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Firebase Auth Signup", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					LocalID string `json:"localId"`
				}
				unmarshal(body, &resp)
				return cr("Firebase Auth Signup", "Firebase", StatusVulnerable, "Anonymous UID: "+resp.LocalID, body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Firebase Auth Signup", "Firebase", StatusForbidden, "Key valid, API not enabled or signup disabled", body)
			}
			return cr("Firebase Auth Signup", "Firebase", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_22() ServiceCheck {
	return ServiceCheck{
		Name: "Firebase Auth Providers", Category: "Firebase", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=" + key
			payload := map[string]interface{}{
				"identifier":  "test@test.com",
				"continueUri": "http://localhost",
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Firebase Auth Providers", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					AllProviders []string `json:"allProviders"`
					SigninMethods []string `json:"signinMethods"`
				}
				unmarshal(body, &resp)
				providers := resp.AllProviders
				if len(providers) == 0 {
					providers = resp.SigninMethods
				}
				detail := "Sign-in providers: " + strings.Join(providers, ", ")
				if len(providers) == 0 {
					detail = "Auth API accessible, no providers for test@test.com"
				}
				return cr("Firebase Auth Providers", "Firebase", StatusVulnerable, detail, body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Firebase Auth Providers", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Firebase Auth Providers", "Firebase", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_23() ServiceCheck {
	return ServiceCheck{
		Name: "Firebase RTDB", Category: "Firebase", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			// Try multiple RTDB URL patterns: default, regional, and project-name only.
			// Collect the most permissive result — don't stop early on 403 since
			// another URL may be open.
			urls := []string{
				fmt.Sprintf("https://%s-default-rtdb.firebaseio.com/.json?auth=%s&shallow=true", projectID, key),
				fmt.Sprintf("https://%s-default-rtdb.europe-west1.firebasedatabase.app/.json?auth=%s&shallow=true", projectID, key),
				fmt.Sprintf("https://%s-default-rtdb.asia-southeast1.firebasedatabase.app/.json?auth=%s&shallow=true", projectID, key),
				fmt.Sprintf("https://%s.firebaseio.com/.json?auth=%s&shallow=true", projectID, key),
			}
			var bestForbidden *CheckResult
			for _, u := range urls {
				code, body, err := doGet(u)
				if err != nil {
					continue
				}
				if code == 200 {
					return cr("Firebase RTDB", "Firebase", StatusVulnerable, "Open read access to root node", body)
				}
				if (code == 401 || code == 403) && bestForbidden == nil {
					r := cr("Firebase RTDB", "Firebase", StatusForbidden, "Key valid, read access denied", body)
					bestForbidden = &r
				}
			}
			if bestForbidden != nil {
				return *bestForbidden
			}
			return cr("Firebase RTDB", "Firebase", StatusError, "No RTDB instance found (tried default, EU, Asia, and bare project name)", nil)
		},
	}
}

func check4_24() ServiceCheck {
	return ServiceCheck{
		Name: "Firebase Remote Config", Category: "Firebase", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://firebaseremoteconfig.googleapis.com/v1/projects/%s/remoteConfig?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Firebase Remote Config", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Firebase Remote Config", "Firebase", StatusVulnerable, "Remote config exposed", body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase Remote Config", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Firebase Remote Config", "Firebase", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_25() ServiceCheck {
	return ServiceCheck{
		Name: "Firebase Cloud Messaging", Category: "Firebase", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send?key=%s", projectID, key)
			payload := map[string]interface{}{
				"validate_only": true,
				"message": map[string]interface{}{
					"topic": "test",
					"notification": map[string]interface{}{
						"title": "PoC",
					},
				},
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Firebase Cloud Messaging", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Firebase Cloud Messaging", "Firebase", StatusVulnerable, "FCM send capability confirmed (dry run)", body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase Cloud Messaging", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Firebase Cloud Messaging", "Firebase", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

// ─── Google Maps & Geo checks ────────────────────────────────────────────────

func check4_26() ServiceCheck {
	return ServiceCheck{
		Name: "Maps JavaScript API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/js?key=" + key
			code, _, err := doGet(url)
			if err != nil {
				return cr("Maps JavaScript API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				// Response is JavaScript, not JSON — don't store as RawJSON
				return cr("Maps JavaScript API", "Maps", StatusVulnerable, "Maps JS loads successfully (billing abuse potential)", nil)
			}
			if code == 401 || code == 403 {
				return cr("Maps JavaScript API", "Maps", StatusForbidden, "Key valid, API not enabled", nil)
			}
			return cr("Maps JavaScript API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), nil)
		},
	}
}

func check4_27() ServiceCheck {
	return ServiceCheck{
		Name: "Geocoding API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Geocoding API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status  string `json:"status"`
					Results []struct {
						Geometry struct {
							Location struct {
								Lat float64 `json:"lat"`
								Lng float64 `json:"lng"`
							} `json:"location"`
						} `json:"geometry"`
					} `json:"results"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" && len(resp.Results) > 0 {
					loc := resp.Results[0].Geometry.Location
					return cr("Geocoding API", "Maps", StatusVulnerable, fmt.Sprintf("lat=%.4f, lng=%.4f", loc.Lat, loc.Lng), body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Geocoding API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Geocoding API", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return cr("Geocoding API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_28() ServiceCheck {
	return ServiceCheck{
		Name: "Places API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Places API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" || resp.Status == "ZERO_RESULTS" {
					return cr("Places API", "Maps", StatusVulnerable, "Places API access confirmed (high billing cost)", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Places API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Places API", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return cr("Places API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_29() ServiceCheck {
	return ServiceCheck{
		Name: "Directions API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/directions/json?origin=Toronto&destination=Montreal&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Directions API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					return cr("Directions API", "Maps", StatusVulnerable, "Directions API access confirmed", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Directions API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Directions API", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return cr("Directions API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_30() ServiceCheck {
	return ServiceCheck{
		Name: "Distance Matrix API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/distancematrix/json?origins=Toronto&destinations=Montreal&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Distance Matrix API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					return cr("Distance Matrix API", "Maps", StatusVulnerable, "Distance Matrix API access confirmed", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Distance Matrix API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Distance Matrix API", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return cr("Distance Matrix API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_31() ServiceCheck {
	return ServiceCheck{
		Name: "Elevation API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Elevation API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					return cr("Elevation API", "Maps", StatusVulnerable, "Elevation API access confirmed", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Elevation API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Elevation API", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return cr("Elevation API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_32() ServiceCheck {
	return ServiceCheck{
		Name: "Static Maps API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/staticmap?center=Brooklyn+Bridge&zoom=13&size=10x10&key=" + key
			code, _, err := doGet(url)
			if err != nil {
				return cr("Static Maps API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				// Response is binary image data, not JSON
				return cr("Static Maps API", "Maps", StatusVulnerable, "Static Maps access confirmed (billing abuse)", nil)
			}
			if code == 401 || code == 403 {
				return cr("Static Maps API", "Maps", StatusForbidden, "Key valid, API not enabled", nil)
			}
			return cr("Static Maps API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), nil)
		},
	}
}

func check4_33() ServiceCheck {
	return ServiceCheck{
		Name: "Street View API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/streetview?size=10x10&location=40.720032,-73.988354&key=" + key
			code, _, err := doGet(url)
			if err != nil {
				return cr("Street View API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				// Response is binary image data, not JSON
				return cr("Street View API", "Maps", StatusVulnerable, "Street View access confirmed", nil)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Street View API", "Maps", StatusForbidden, "Key valid, API not enabled", nil)
			}
			return cr("Street View API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), nil)
		},
	}
}

func check4_34() ServiceCheck {
	return ServiceCheck{
		Name: "Time Zone API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Time Zone API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					return cr("Time Zone API", "Maps", StatusVulnerable, "Time Zone API access confirmed", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Time Zone API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Time Zone API", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return cr("Time Zone API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_35() ServiceCheck {
	return ServiceCheck{
		Name: "Roads API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Roads API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Roads API", "Maps", StatusVulnerable, "Roads API access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Roads API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Roads API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_36() ServiceCheck {
	return ServiceCheck{
		Name: "Custom Search API", Category: "Search", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			// Uses a public example search engine (cx). A 200 confirms the key has
			// Custom Search API + billing enabled, but does NOT mean the key controls
			// any custom search engine — only that it can make billable queries.
			url := "https://www.googleapis.com/customsearch/v1?q=test&cx=017576662512468239146:omuauf_lfve&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Custom Search API", "Search", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Custom Search API", "Search", StatusVulnerable, "Custom Search API enabled (billing access confirmed)", body)
			}
			if code == 401 || code == 403 {
				return cr("Custom Search API", "Search", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Custom Search API", "Search", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

// ─── Extra Maps & Geo checks ─────────────────────────────────────────────────

func checkPlacesAutocomplete() ServiceCheck {
	return ServiceCheck{
		Name: "Places Autocomplete", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Googleplex&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Places Autocomplete", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct{ Status string `json:"status"` }
				unmarshal(body, &resp)
				if resp.Status == "OK" || resp.Status == "ZERO_RESULTS" {
					return cr("Places Autocomplete", "Maps", StatusVulnerable, "Places Autocomplete access confirmed ($2.83/1k reqs)", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Places Autocomplete", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Places Autocomplete", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return cr("Places Autocomplete", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkPlacesDetails() ServiceCheck {
	return ServiceCheck{
		Name: "Places Details", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Places Details", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct{ Status string `json:"status"` }
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					return cr("Places Details", "Maps", StatusVulnerable, "Places Details access confirmed ($17/1k reqs)", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Places Details", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Places Details", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return cr("Places Details", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkMapsTile() ServiceCheck {
	return ServiceCheck{
		Name: "Map Tiles API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://tile.googleapis.com/v1/createSession?key=" + key
			payload := map[string]interface{}{
				"mapType":   "roadmap",
				"language":  "en-US",
				"region":    "US",
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Map Tiles API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Map Tiles API", "Maps", StatusVulnerable, "Map Tiles session creation confirmed", body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Map Tiles API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Map Tiles API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkEmbedAPI() ServiceCheck {
	return ServiceCheck{
		Name: "Maps Embed API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://www.google.com/maps/embed/v1/place?q=NYC&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Maps Embed API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Maps Embed API", "Maps", StatusVulnerable, "Maps Embed access confirmed", body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Maps Embed API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Maps Embed API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkSolarAPI() ServiceCheck {
	return ServiceCheck{
		Name: "Solar API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://solar.googleapis.com/v1/buildingInsights:findClosest?location.latitude=37.4219999&location.longitude=-122.0840575&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Solar API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Solar API", "Maps", StatusVulnerable, "Solar API access confirmed ($15-$25/1k reqs)", body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Solar API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Solar API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkAirQuality() ServiceCheck {
	return ServiceCheck{
		Name: "Air Quality API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://airquality.googleapis.com/v1/currentConditions:lookup?key=" + key
			payload := map[string]interface{}{
				"location": map[string]interface{}{
					"latitude":  37.419734,
					"longitude": -122.0827784,
				},
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Air Quality API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Air Quality API", "Maps", StatusVulnerable, "Air Quality API access confirmed ($5/1k reqs)", body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Air Quality API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Air Quality API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

// ─── AI & Machine Learning checks ────────────────────────────────────────────

func check4_37() ServiceCheck {
	return ServiceCheck{
		Name: "Gemini", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" + key
			payload := map[string]interface{}{
				"contents": []map[string]interface{}{
					{"parts": []map[string]interface{}{
						{"text": "Say the word: hello"},
					}},
				},
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Gemini", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Candidates []struct {
						Content struct {
							Parts []struct {
								Text string `json:"text"`
							} `json:"parts"`
						} `json:"content"`
					} `json:"candidates"`
				}
				unmarshal(body, &resp)
				detail := "Gemini API access confirmed"
				if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
					text := resp.Candidates[0].Content.Parts[0].Text
					if len(text) > 50 {
						text = text[:50] + "..."
					}
					detail = "Response: " + strings.TrimSpace(text)
				}
				return cr("Gemini", "AI", StatusVulnerable, detail, body)
			}
			if code == 400 || code == 401 || code == 403 || code == 404 {
				return cr("Gemini", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Gemini", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_38() ServiceCheck {
	return ServiceCheck{
		Name: "Gemini Models", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://generativelanguage.googleapis.com/v1beta/models?key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Gemini Models", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Models []struct {
						Name string `json:"name"`
					} `json:"models"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, m := range resp.Models {
					names = append(names, shortName(m.Name))
				}
				detail := fmt.Sprintf("%d models accessible", len(resp.Models))
				if len(names) > 5 {
					names = names[:5]
					detail += ": " + strings.Join(names, ", ") + ", ..."
				} else if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Gemini Models", "AI", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Gemini Models", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Gemini Models", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_39() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Translation", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://translation.googleapis.com/language/translate/v2?key=" + key
			payload := map[string]interface{}{
				"q":      "hello",
				"target": "es",
				"format": "text",
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Cloud Translation", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Cloud Translation", "AI", StatusVulnerable, "Translation API billing access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Translation", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Translation", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_40() ServiceCheck {
	return ServiceCheck{
		Name: "Language Detection", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://translation.googleapis.com/language/translate/v2/detect?key=" + key
			payload := map[string]interface{}{"q": "Hello World"}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Language Detection", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Language Detection", "AI", StatusVulnerable, "Language detection API access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Language Detection", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Language Detection", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_41() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Vision", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://vision.googleapis.com/v1/images:annotate?key=" + key
			// 1x1 white PNG base64
			payload := map[string]interface{}{
				"requests": []map[string]interface{}{
					{
						"image": map[string]interface{}{
							"content": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==",
						},
						"features": []map[string]interface{}{
							{"type": "LABEL_DETECTION", "maxResults": 1},
						},
					},
				},
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Cloud Vision", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Cloud Vision", "AI", StatusVulnerable, "Vision API billing access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Vision", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Vision", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_42() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud NLP", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://language.googleapis.com/v1/documents:analyzeSentiment?key=" + key
			payload := map[string]interface{}{
				"document":     map[string]interface{}{"type": "PLAIN_TEXT", "content": "Hello World"},
				"encodingType": "UTF8",
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Cloud NLP", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Cloud NLP", "AI", StatusVulnerable, "NLP API access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud NLP", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud NLP", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_43() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Speech-to-Text", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			// POST with empty body: 400 = API enabled (bad request), 403 = API disabled
			url := "https://speech.googleapis.com/v1/speech:recognize?key=" + key
			code, body, err := doPost(url, map[string]interface{}{})
			if err != nil {
				return cr("Cloud Speech-to-Text", "AI", StatusError, err.Error(), nil)
			}
			if code == 400 {
				return cr("Cloud Speech-to-Text", "AI", StatusVulnerable, "API is enabled (key accepted, empty-body probe)", body)
			}
			if code == 200 {
				return cr("Cloud Speech-to-Text", "AI", StatusVulnerable, "Speech API access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Speech-to-Text", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Speech-to-Text", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_44() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Text-to-Speech", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://texttospeech.googleapis.com/v1/voices?key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Text-to-Speech", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Voices []interface{} `json:"voices"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("TTS API access confirmed, %d voices available", len(resp.Voices))
				return cr("Cloud Text-to-Speech", "AI", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Text-to-Speech", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Text-to-Speech", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_45() ServiceCheck {
	return ServiceCheck{
		Name: "Vertex AI", Category: "AI", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://us-central1-aiplatform.googleapis.com/v1/projects/%s/locations/us-central1/models?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Vertex AI", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Models []struct {
						DisplayName string `json:"displayName"`
					} `json:"models"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, m := range resp.Models {
					names = append(names, m.DisplayName)
				}
				detail := fmt.Sprintf("%d deployed models", len(resp.Models))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Vertex AI", "AI", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Vertex AI", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Vertex AI", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_46() ServiceCheck {
	return ServiceCheck{
		Name: "AutoML", Category: "AI", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://automl.googleapis.com/v1/projects/%s/locations/us-central1/datasets?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("AutoML", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Datasets []struct {
						DisplayName string `json:"displayName"`
					} `json:"datasets"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, d := range resp.Datasets {
					names = append(names, d.DisplayName)
				}
				detail := fmt.Sprintf("%d datasets", len(resp.Datasets))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("AutoML", "AI", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("AutoML", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("AutoML", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

// ─── Media & Content checks ─────────────────────────────────────────────────

func check4_47() ServiceCheck {
	return ServiceCheck{
		Name: "YouTube Search", Category: "Media", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&type=video&maxResults=1&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("YouTube Search", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("YouTube Search", "Media", StatusVulnerable, "YouTube Data API access confirmed (quota abuse)", body)
			}
			if code == 401 || code == 403 {
				return cr("YouTube Search", "Media", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("YouTube Search", "Media", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_48() ServiceCheck {
	return ServiceCheck{
		Name: "YouTube Channels", Category: "Media", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("YouTube Channels", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("YouTube Channels", "Media", StatusVulnerable, "YouTube channel data accessible", body)
			}
			if code == 401 || code == 403 {
				return cr("YouTube Channels", "Media", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return cr("YouTube Channels", "Media", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_49() ServiceCheck {
	return ServiceCheck{
		Name: "YouTube Analytics", Category: "Media", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==MINE&metrics=views&startDate=2024-01-01&endDate=2024-01-02&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("YouTube Analytics", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("YouTube Analytics", "Media", StatusVulnerable, "YouTube Analytics API access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("YouTube Analytics", "Media", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return cr("YouTube Analytics", "Media", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_50() ServiceCheck {
	return ServiceCheck{
		Name: "Google Books", Category: "Media", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/books/v1/volumes?q=golang&maxResults=1&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Google Books", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Google Books", "Media", StatusVulnerable, "Books API access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Google Books", "Media", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Google Books", "Media", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_51() ServiceCheck {
	return ServiceCheck{
		Name: "Google Fonts", Category: "Media", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/webfonts/v1/webfonts?key=" + key + "&sort=popularity"
			code, body, err := doGet(url)
			if err != nil {
				return cr("Google Fonts", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Google Fonts", "Media", StatusVulnerable, "Fonts API access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Google Fonts", "Media", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Google Fonts", "Media", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_52() ServiceCheck {
	return ServiceCheck{
		Name: "Google Calendar", Category: "Media", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/calendar/v3/users/me/calendarList?key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Google Calendar", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Google Calendar", "Media", StatusVulnerable, "Calendar API access confirmed (misconfigured!)", body)
			}
			if code == 401 || code == 403 {
				return cr("Google Calendar", "Media", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return cr("Google Calendar", "Media", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_53() ServiceCheck {
	return ServiceCheck{
		Name: "Google Drive", Category: "Media", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/drive/v3/files?key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Google Drive", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Google Drive", "Media", StatusVulnerable, "Drive API access confirmed (misconfigured!)", body)
			}
			if code == 401 || code == 403 {
				return cr("Google Drive", "Media", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return cr("Google Drive", "Media", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_54() ServiceCheck {
	return ServiceCheck{
		Name: "Google Sheets", Category: "Media", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://sheets.googleapis.com/v4/spreadsheets?key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Google Sheets", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Google Sheets", "Media", StatusVulnerable, "Sheets API access confirmed (misconfigured!)", body)
			}
			if code == 401 || code == 403 || code == 404 {
				return cr("Google Sheets", "Media", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return cr("Google Sheets", "Media", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

// ─── Identity & Security checks ──────────────────────────────────────────────

func check4_55() ServiceCheck {
	return ServiceCheck{
		Name: "People API", Category: "Identity", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			url := "https://people.googleapis.com/v1/people:listDirectoryPeople?sources=DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE&readMask=names&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("People API", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("People API", "Identity", StatusVulnerable, "Corporate directory access confirmed!", body)
			}
			if code == 401 || code == 403 {
				return cr("People API", "Identity", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return cr("People API", "Identity", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_56() ServiceCheck {
	return ServiceCheck{
		Name: "reCAPTCHA Enterprise", Category: "Identity", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://recaptchaenterprise.googleapis.com/v1/projects/%s/keys?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("reCAPTCHA Enterprise", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Keys []struct {
						Name string `json:"name"`
					} `json:"keys"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d reCAPTCHA site keys", len(resp.Keys))
				return cr("reCAPTCHA Enterprise", "Identity", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("reCAPTCHA Enterprise", "Identity", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("reCAPTCHA Enterprise", "Identity", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_57() ServiceCheck {
	return ServiceCheck{
		Name: "Identity-Aware Proxy", Category: "Identity", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://iap.googleapis.com/v1/projects/%s/iap_web?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Identity-Aware Proxy", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Identity-Aware Proxy", "Identity", StatusVulnerable, "IAP configuration accessible", body)
			}
			if code == 401 || code == 403 {
				return cr("Identity-Aware Proxy", "Identity", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Identity-Aware Proxy", "Identity", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_58() ServiceCheck {
	return ServiceCheck{
		Name: "Service Usage", Category: "Identity", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://serviceusage.googleapis.com/v1/projects/%s/services?filter=state:ENABLED&key=%s&pageSize=20", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Service Usage", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Services []struct {
						Config struct {
							Name string `json:"name"`
						} `json:"config"`
					} `json:"services"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, s := range resp.Services {
					names = append(names, s.Config.Name)
				}
				detail := fmt.Sprintf("%d enabled APIs", len(resp.Services))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Service Usage", "Identity", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Service Usage", "Identity", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Service Usage", "Identity", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func check4_59() ServiceCheck {
	return ServiceCheck{
		Name: "IAM Service Accounts", Category: "Identity", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://iam.googleapis.com/v1/projects/%s/serviceAccounts?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("IAM Service Accounts", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Accounts []struct {
						Email string `json:"email"`
					} `json:"accounts"`
				}
				unmarshal(body, &resp)
				var emails []string
				for _, a := range resp.Accounts {
					emails = append(emails, a.Email)
				}
				detail := fmt.Sprintf("%d service accounts", len(resp.Accounts))
				if len(emails) > 0 {
					detail += ": " + strings.Join(emails, ", ")
				}
				return cr("IAM Service Accounts", "Identity", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("IAM Service Accounts", "Identity", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("IAM Service Accounts", "Identity", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

// ─── New GCP Infrastructure checks ──────────────────────────────────────────

func checkMemorystore() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Memorystore", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://redis.googleapis.com/v1/projects/%s/locations/-/instances?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Memorystore", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Instances []struct {
						Name string `json:"name"`
					} `json:"instances"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d Redis instances", len(resp.Instances))
				if len(resp.Instances) > 0 {
					var names []string
					for _, inst := range resp.Instances {
						names = append(names, shortName(inst.Name))
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Memorystore", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Memorystore", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Memorystore", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkFilestore() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Filestore", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://file.googleapis.com/v1/projects/%s/locations/-/instances?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Filestore", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Instances []struct {
						Name string `json:"name"`
					} `json:"instances"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d Filestore instances", len(resp.Instances))
				if len(resp.Instances) > 0 {
					var names []string
					for _, inst := range resp.Instances {
						names = append(names, shortName(inst.Name))
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Filestore", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Filestore", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Filestore", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkVPCNetworks() ServiceCheck {
	return ServiceCheck{
		Name: "VPC Networks", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("VPC Networks", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Items []struct {
						Name string `json:"name"`
					} `json:"items"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d VPC networks", len(resp.Items))
				if len(resp.Items) > 0 {
					var names []string
					for _, n := range resp.Items {
						names = append(names, n.Name)
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("VPC Networks", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("VPC Networks", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("VPC Networks", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkCloudEndpoints() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Endpoints", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://servicemanagement.googleapis.com/v1/services?producerProjectId=%s&key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Endpoints", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Services []struct {
						ServiceName string `json:"serviceName"`
					} `json:"services"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d managed services", len(resp.Services))
				if len(resp.Services) > 0 {
					var names []string
					for _, s := range resp.Services {
						names = append(names, s.ServiceName)
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Endpoints", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Endpoints", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Endpoints", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkFirebaseExtensions() ServiceCheck {
	return ServiceCheck{
		Name: "Firebase Extensions", Category: "Firebase", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebaseextensions.googleapis.com/v1beta/projects/%s/instances?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase Extensions", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Instances []struct {
						Name string `json:"name"`
					} `json:"instances"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d extension instances", len(resp.Instances))
				return cr("Firebase Extensions", "Firebase", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase Extensions", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Firebase Extensions", "Firebase", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkFirebaseTestLab() ServiceCheck {
	return ServiceCheck{
		Name: "Firebase Test Lab", Category: "Firebase", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://testing.googleapis.com/v1/testEnvironmentCatalog/ANDROID?key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase Test Lab", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Models []struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"models"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d Android device models in catalog", len(resp.Models))
				return cr("Firebase Test Lab", "Firebase", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase Test Lab", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Firebase Test Lab", "Firebase", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkFirebaseHosting() ServiceCheck {
	return ServiceCheck{
		Name: "Firebase Hosting", Category: "Firebase", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebasehosting.googleapis.com/v1beta1/projects/%s/sites?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase Hosting", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Sites []struct {
						Name       string `json:"name"`
						DefaultURL string `json:"defaultUrl"`
					} `json:"sites"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d hosting sites", len(resp.Sites))
				if len(resp.Sites) > 0 {
					var urls []string
					for _, s := range resp.Sites {
						if s.DefaultURL != "" {
							urls = append(urls, s.DefaultURL)
						} else {
							urls = append(urls, shortName(s.Name))
						}
					}
					detail += ": " + strings.Join(urls, ", ")
				}
				return cr("Firebase Hosting", "Firebase", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase Hosting", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Firebase Hosting", "Firebase", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkCloudWorkflows() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Workflows", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://workflows.googleapis.com/v1/projects/%s/locations/-/workflows?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Workflows", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Workflows []struct {
						Name string `json:"name"`
					} `json:"workflows"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d workflows", len(resp.Workflows))
				if len(resp.Workflows) > 0 {
					var names []string
					for _, w := range resp.Workflows {
						names = append(names, shortName(w.Name))
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Workflows", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Workflows", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Workflows", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

// ─── New Maps & Geo checks ──────────────────────────────────────────────────

func checkAddressValidation() ServiceCheck {
	return ServiceCheck{
		Name: "Address Validation", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://addressvalidation.googleapis.com/v1:validateAddress?key=" + key
			payload := map[string]interface{}{
				"address": map[string]interface{}{
					"addressLines": []string{"1600 Amphitheatre Parkway, Mountain View, CA"},
				},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Address Validation", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Address Validation", "Maps", StatusVulnerable, "Address Validation API access confirmed ($0.005/call)", body)
			}
			if code == 401 || code == 403 {
				return cr("Address Validation", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Address Validation", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkRoutesAPI() ServiceCheck {
	return ServiceCheck{
		Name: "Routes API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://routes.googleapis.com/directions/v2:computeRoutes?key=" + key
			payload := map[string]interface{}{
				"origin":      map[string]interface{}{"location": map[string]interface{}{"latLng": map[string]interface{}{"latitude": 37.4191, "longitude": -122.0574}}},
				"destination": map[string]interface{}{"location": map[string]interface{}{"latLng": map[string]interface{}{"latitude": 37.418, "longitude": -122.079}}},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Routes API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Routes API", "Maps", StatusVulnerable, "Routes API v2 access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Routes API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Routes API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkRouteMatrix() ServiceCheck {
	return ServiceCheck{
		Name: "Route Matrix API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key=" + key
			payload := map[string]interface{}{
				"origins":      []map[string]interface{}{{"waypoint": map[string]interface{}{"location": map[string]interface{}{"latLng": map[string]interface{}{"latitude": 37.4191, "longitude": -122.0574}}}}},
				"destinations": []map[string]interface{}{{"waypoint": map[string]interface{}{"location": map[string]interface{}{"latLng": map[string]interface{}{"latitude": 37.418, "longitude": -122.079}}}}},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Route Matrix API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Route Matrix API", "Maps", StatusVulnerable, "Route Matrix API v2 access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Route Matrix API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Route Matrix API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkAerialView() ServiceCheck {
	return ServiceCheck{
		Name: "Aerial View", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://aerialview.googleapis.com/v1/videos:lookupVideo?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Aerial View", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Aerial View", "Maps", StatusVulnerable, "Aerial View API access confirmed", body)
			}
			// 404 means API is enabled but no aerial video exists for this address
			if code == 404 {
				return cr("Aerial View", "Maps", StatusVulnerable, "API enabled (no video for this address)", body)
			}
			if code == 401 || code == 403 {
				return cr("Aerial View", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Aerial View", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkPlacesNew() ServiceCheck {
	return ServiceCheck{
		Name: "Places API (New)", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://places.googleapis.com/v1/places:searchNearby?key=" + key
			payload := map[string]interface{}{
				"locationRestriction": map[string]interface{}{
					"circle": map[string]interface{}{
						"center": map[string]interface{}{"latitude": 37.4191, "longitude": -122.0574},
						"radius": 100.0,
					},
				},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Places API (New)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Places []struct {
						DisplayName struct {
							Text string `json:"text"`
						} `json:"displayName"`
					} `json:"places"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d nearby places", len(resp.Places))
				return cr("Places API (New)", "Maps", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Places API (New)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Places API (New)", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkPollenAPI() ServiceCheck {
	return ServiceCheck{
		Name: "Pollen API", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://pollen.googleapis.com/v1/forecast:lookup?location.latitude=37.4&location.longitude=-122.0&days=1&key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Pollen API", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Pollen API", "Maps", StatusVulnerable, "Pollen API access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Pollen API", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Pollen API", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

// ─── New AI & ML checks ─────────────────────────────────────────────────────

func checkGeminiTunedModels() ServiceCheck {
	return ServiceCheck{
		Name: "Gemini Tuned Models", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://generativelanguage.googleapis.com/v1beta/tunedModels?key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Gemini Tuned Models", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					TunedModels []struct {
						Name string `json:"name"`
					} `json:"tunedModels"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d tuned models", len(resp.TunedModels))
				return cr("Gemini Tuned Models", "AI", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Gemini Tuned Models", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Gemini Tuned Models", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkVertexAIDatasets() ServiceCheck {
	return ServiceCheck{
		Name: "Vertex AI Datasets", Category: "AI", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://us-central1-aiplatform.googleapis.com/v1/projects/%s/locations/us-central1/datasets?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Vertex AI Datasets", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Datasets []struct {
						DisplayName string `json:"displayName"`
					} `json:"datasets"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, d := range resp.Datasets {
					names = append(names, d.DisplayName)
				}
				detail := fmt.Sprintf("%d datasets", len(resp.Datasets))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Vertex AI Datasets", "AI", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Vertex AI Datasets", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Vertex AI Datasets", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkGeminiFiles() ServiceCheck {
	return ServiceCheck{
		Name: "Gemini Files API", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://generativelanguage.googleapis.com/v1beta/files?key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Gemini Files API", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Files []struct {
						Name string `json:"name"`
					} `json:"files"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d uploaded files accessible (potential data leak)", len(resp.Files))
				return cr("Gemini Files API", "AI", StatusVulnerable, detail, body)
			}
			if code == 404 {
				return cr("Gemini Files API", "AI", StatusError, "HTTP 404 — endpoint not found", body)
			}
			if code == 401 || code == 403 {
				return cr("Gemini Files API", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Gemini Files API", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkVideoIntelligence() ServiceCheck {
	return ServiceCheck{
		Name: "Video Intelligence", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			// POST with empty body: 400 = API enabled (bad request), 403 = API disabled
			u := "https://videointelligence.googleapis.com/v1/videos:annotate?key=" + key
			code, body, err := doPost(u, map[string]interface{}{})
			if err != nil {
				return cr("Video Intelligence", "AI", StatusError, err.Error(), nil)
			}
			if code == 400 {
				return cr("Video Intelligence", "AI", StatusVulnerable, "API is enabled (key accepted, empty-body probe)", body)
			}
			if code == 200 {
				return cr("Video Intelligence", "AI", StatusVulnerable, "Video Intelligence API access confirmed", body)
			}
			if code == 401 || code == 403 {
				return cr("Video Intelligence", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Video Intelligence", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkDocumentAI() ServiceCheck {
	return ServiceCheck{
		Name: "Document AI", Category: "AI", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://us-documentai.googleapis.com/v1/projects/%s/locations/us/processors?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Document AI", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Processors []struct {
						Name string `json:"name"`
					} `json:"processors"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d Document AI processors", len(resp.Processors))
				return cr("Document AI", "AI", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Document AI", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Document AI", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

// ─── New Identity checks ────────────────────────────────────────────────────

func checkFirebaseAppCheck() ServiceCheck {
	return ServiceCheck{
		Name: "Firebase App Check", Category: "Identity", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebaseappcheck.googleapis.com/v1/projects/%s/apps?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase App Check", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Apps []struct {
						Name string `json:"name"`
					} `json:"apps"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d registered apps", len(resp.Apps))
				return cr("Firebase App Check", "Identity", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase App Check", "Identity", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Firebase App Check", "Identity", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkSourceRepos() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Source Repositories", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://sourcerepo.googleapis.com/v1/projects/%s/repos?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Source Repositories", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Repos []struct {
						Name string `json:"name"`
					} `json:"repos"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d repositories", len(resp.Repos))
				return cr("Cloud Source Repositories", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Source Repositories", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Source Repositories", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkCloudKMS() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud KMS", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://cloudkms.googleapis.com/v1/projects/%s/locations/-/keyRings?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud KMS", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					KeyRings []struct {
						Name string `json:"name"`
					} `json:"keyRings"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d key rings", len(resp.KeyRings))
				return cr("Cloud KMS", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud KMS", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud KMS", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkDataflow() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Dataflow", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://dataflow.googleapis.com/v1b3/projects/%s/jobs?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Dataflow", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Jobs []struct {
						Name string `json:"name"`
					} `json:"jobs"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d jobs", len(resp.Jobs))
				return cr("Cloud Dataflow", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Dataflow", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Dataflow", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkFindPlace() ServiceCheck {
	return ServiceCheck{
		Name: "Find Place", Category: "Maps", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum+of+Contemporary+Art+Australia&inputtype=textquery&key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Find Place", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status     string `json:"status"`
					Candidates []struct {
						PlaceID string `json:"place_id"`
					} `json:"candidates"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					detail := fmt.Sprintf("%d candidates", len(resp.Candidates))
					return cr("Find Place", "Maps", StatusVulnerable, detail, body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Find Place", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Find Place", "Maps", StatusError, "status: "+resp.Status, body)
			}
			if code == 401 || code == 403 {
				return cr("Find Place", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Find Place", "Maps", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkGeminiEmbeddings() ServiceCheck {
	return ServiceCheck{
		Name: "Gemini Embeddings", Category: "AI", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent?key=" + key
			payload := map[string]interface{}{
				"content": map[string]interface{}{
					"parts": []map[string]interface{}{
						{"text": "Hello"},
					},
				},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Gemini Embeddings", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Embedding struct {
						Values []float64 `json:"values"`
					} `json:"embedding"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("embedding dim %d", len(resp.Embedding.Values))
				return cr("Gemini Embeddings", "AI", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Gemini Embeddings", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Gemini Embeddings", "AI", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkCloudComposer() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Composer", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://composer.googleapis.com/v1/projects/%s/locations/-/environments?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Composer", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Environments []struct {
						Name string `json:"name"`
					} `json:"environments"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d Composer environments", len(resp.Environments))
				if len(resp.Environments) > 0 {
					var names []string
					for _, e := range resp.Environments {
						names = append(names, shortName(e.Name))
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Composer", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Composer", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Composer", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkAlloyDB() ServiceCheck {
	return ServiceCheck{
		Name: "AlloyDB", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://alloydb.googleapis.com/v1/projects/%s/locations/-/clusters?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("AlloyDB", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Clusters []struct {
						Name string `json:"name"`
					} `json:"clusters"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d AlloyDB clusters", len(resp.Clusters))
				if len(resp.Clusters) > 0 {
					var names []string
					for _, c := range resp.Clusters {
						names = append(names, shortName(c.Name))
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("AlloyDB", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("AlloyDB", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("AlloyDB", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkBatchAPI() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Batch", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://batch.googleapis.com/v1/projects/%s/locations/-/jobs?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Batch", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Jobs []struct {
						Name string `json:"name"`
					} `json:"jobs"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d batch jobs", len(resp.Jobs))
				return cr("Cloud Batch", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Batch", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Batch", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkBillingAccounts() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Billing", Category: "GCP", NeedsProject: false,
		Run: func(key, projectID string) CheckResult {
			u := "https://cloudbilling.googleapis.com/v1/billingAccounts?key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Billing", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					BillingAccounts []struct {
						Name        string `json:"name"`
						DisplayName string `json:"displayName"`
						Open        bool   `json:"open"`
					} `json:"billingAccounts"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d billing accounts", len(resp.BillingAccounts))
				if len(resp.BillingAccounts) > 0 {
					var parts []string
					for _, ba := range resp.BillingAccounts {
						s := ba.Name + " " + ba.DisplayName
						if ba.Open {
							s += " (active)"
						}
						parts = append(parts, s)
					}
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Billing", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Billing", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Billing", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

func checkCloudRetail() ServiceCheck {
	return ServiceCheck{
		Name: "Cloud Retail", Category: "GCP", NeedsProject: true,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://retail.googleapis.com/v2/projects/%s/locations/global/catalogs?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Retail", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Catalogs []struct {
						Name string `json:"name"`
					} `json:"catalogs"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d catalogs", len(resp.Catalogs))
				return cr("Cloud Retail", "GCP", StatusVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Retail", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return cr("Cloud Retail", "GCP", StatusError, fmt.Sprintf("HTTP %d", code), body)
		},
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func cr(service, category string, status Status, detail string, rawBody []byte) CheckResult {
	return CheckResult{
		Service:  service,
		Category: category,
		Status:   status,
		StatusS:  status.String(),
		Detail:   detail,
		RawJSON:  rawIf(rawBody),
	}
}

func shortName(full string) string {
	parts := strings.Split(full, "/")
	return parts[len(parts)-1]
}

// ─── Output ──────────────────────────────────────────────────────────────────

func printResult(r CheckResult) {
	if silent > 0 {
		return
	}
	printMu.Lock()
	defer printMu.Unlock()

	var tag string
	switch r.Status {
	case StatusVulnerable:
		tag = colorVuln.Sprintf("[VULNERABLE]")
	case StatusForbidden:
		tag = colorForb.Sprintf("[FORBIDDEN] ")
	case StatusInvalid:
		tag = colorInv.Sprintf("[INVALID]   ")
	case StatusError:
		tag = colorErr.Sprintf("[ERROR]     ")
	}

	cat := r.Category
	if cat == "" {
		cat = "---"
	}
	fmt.Printf("%-14s %-8s / %-25s | %s\n", tag, cat, r.Service, r.Detail)

	if verbose && r.RawJSON != "" {
		fmt.Println("  RAW:", r.RawJSON)
	}
}

func printSummary(kr KeyResult) {
	if silent > 1 {
		return
	}
	printMu.Lock()
	defer printMu.Unlock()

	maskedKey := kr.Key
	if len(maskedKey) > 10 {
		maskedKey = maskedKey[:10] + "..." + maskedKey[len(maskedKey)-5:]
	}

	vulnCount := 0
	enabledCount := 0

	for _, c := range kr.Results {
		if c.Status == StatusVulnerable {
			vulnCount++
		}
		if c.Service == "Service Usage" && c.Status == StatusVulnerable {
			// Extract count: detail starts with "<N> enabled APIs"
			if idx := strings.Index(c.Detail, " enabled API"); idx > 0 {
				fmt.Sscanf(c.Detail[:idx], "%d", &enabledCount)
			}
		}
	}

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════")
	fmt.Printf("KEY      : %s\n", maskedKey)
	fmt.Printf("PROJECT  : %s\n", kr.ProjectID)
	if enabledCount > 0 {
		fmt.Printf("ENABLED APIs (from Service Usage): %d detected\n", enabledCount)
	}
	fmt.Printf("VULNERABLE SERVICES: %d\n", vulnCount)
	fmt.Println()

	for _, c := range kr.Results {
		if c.Status == StatusVulnerable {
			fmt.Printf("%-8s / %-25s | %s\n", c.Category, c.Service, c.Detail)
		}
	}

	fmt.Println("══════════════════════════════════════════════════")
}

// ─── Key validation pipeline ─────────────────────────────────────────────────

func validateKey(key, fallbackProject string, checks []ServiceCheck) KeyResult {
	kr := KeyResult{
		Key:       key,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// URL-encode the key for safe use in query parameters
	escKey := url.QueryEscape(key)

	gw := gatewayCheck(key, fallbackProject)
	switch gw.status {
	case "invalid":
		printMu.Lock()
		colorInv.Printf("[INVALID]    ---                               | Key rejected by Google (HTTP 400)\n")
		printMu.Unlock()
		kr.Results = append(kr.Results, CheckResult{
			Service: "Gateway", Category: "---", Status: StatusInvalid, StatusS: "invalid",
			Detail: "Key rejected by Google (HTTP 400)",
		})
		return kr
	case "error":
		errDetail := "Gateway check failed: " + gw.errMsg
		printMu.Lock()
		colorErr.Printf("[ERROR]      ---                               | %s\n", errDetail)
		printMu.Unlock()
		kr.Results = append(kr.Results, CheckResult{
			Service: "Gateway", Category: "---", Status: StatusError, StatusS: "error",
			Detail: errDetail,
		})
		return kr
	}

	kr.ProjectID = gw.projectID

	// Inject the Resource Manager result from the gateway check
	if gw.rmResult != nil {
		printResult(*gw.rmResult)
		kr.Results = append(kr.Results, *gw.rmResult)
	}

	var wg sync.WaitGroup
	results := make([]CheckResult, len(checks))

	for i, chk := range checks {
		if chk.NeedsProject && kr.ProjectID == "" {
			results[i] = CheckResult{
				Service: chk.Name, Category: chk.Category, Status: StatusError, StatusS: "error",
				Detail: "Skipped — no project ID available (use -p flag)",
			}
			continue
		}
		wg.Add(1)
		go func(idx int, c ServiceCheck) {
			defer wg.Done()
			results[idx] = c.Run(escKey, kr.ProjectID)
		}(i, chk)
	}
	wg.Wait()

	for _, r := range results {
		printResult(r)
		kr.Results = append(kr.Results, r)
	}

	printSummary(kr)
	return kr
}

// ─── Input collection ────────────────────────────────────────────────────────

func collectKeys(flagKey, flagFile string) []string {
	var keys []string

	if flagKey != "" {
		keys = append(keys, strings.TrimSpace(flagKey))
		return keys
	}

	if flagFile != "" {
		data, err := os.ReadFile(flagFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", flagFile, err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				keys = append(keys, line)
			}
		}
		return keys
	}

	// Try stdin
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				keys = append(keys, line)
			}
		}
	}

	return keys
}

// ─── Main ────────────────────────────────────────────────────────────────────

func main() {
	flagKey := flag.String("k", "", "Single API key")
	flagFile := flag.String("f", "", "File of newline-separated keys")
	flagProject := flag.String("p", "", "Fallback GCP Project ID")
	flagVerbose := flag.Bool("v", false, "Verbose: print full raw JSON responses")
	flagWorkers := flag.Int("w", 5, "Worker pool size")
	flagJsonl := flag.String("j", "", "Output file path (JSONL format)")
	flagOutput := flag.String("o", "", "Output file: save only key + vulnerable services (appends)")
	flagSilent := flag.Bool("s", false, "Silent: print only the summary (nothing if -o or -j is set)")
	flagCategories := flag.String("categories", "", "Comma-separated categories to check (e.g. Maps,AI)")
	flagTimeout := flag.Int("timeout", 10, "Per-request HTTP timeout in seconds")
	flag.Parse()

	verbose = *flagVerbose
	if *flagSilent {
		silent = 1
		if *flagJsonl != "" || *flagOutput != "" {
			silent = 2
		}
	}
	client = &http.Client{
		Timeout: time.Duration(*flagTimeout) * time.Second,
	}

	keys := collectKeys(*flagKey, *flagFile)
	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "No keys provided. Use -k, -f, or pipe via stdin.")
		flag.Usage()
		os.Exit(1)
	}

	// Warn about keys that don't match expected format, with specific credential type hints
	for _, k := range keys {
		if !keyPattern.MatchString(k) {
			trimmed := strings.TrimSpace(k)
			switch {
			case strings.HasPrefix(trimmed, "ya29."):
				fmt.Fprintf(os.Stderr, "[WARN] %q looks like an OAuth2 access token, not an API key\n", trimmed)
			case strings.HasPrefix(trimmed, "{"):
				preview := trimmed
				if len(preview) > 40 {
					preview = preview[:40] + "..."
				}
				fmt.Fprintf(os.Stderr, "[WARN] %q appears to be JSON (service account key?), not an API key\n", preview)
			case strings.HasPrefix(trimmed, "GOCSPX-") || strings.HasPrefix(trimmed, "GOOG"):
				fmt.Fprintf(os.Stderr, "[WARN] %q looks like an OAuth client secret, not an API key\n", trimmed)
			default:
				fmt.Fprintf(os.Stderr, "[WARN] Key %q does not match expected AIzaSy... format\n", k)
			}
		}
	}

	checks := buildChecks()

	// Filter by category if specified
	if *flagCategories != "" {
		allowed := make(map[string]bool)
		for _, c := range strings.Split(*flagCategories, ",") {
			allowed[strings.TrimSpace(c)] = true
		}
		var filtered []ServiceCheck
		for _, c := range checks {
			if allowed[c.Category] {
				filtered = append(filtered, c)
			}
		}
		checks = filtered
	}

	var jsonlFile *os.File
	if *flagJsonl != "" {
		var err error
		jsonlFile, err = os.OpenFile(*flagJsonl, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening JSONL file: %v\n", err)
			os.Exit(1)
		}
		defer jsonlFile.Close()
	}

	var outputFile *os.File
	if *flagOutput != "" {
		var err error
		outputFile, err = os.OpenFile(*flagOutput, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
			os.Exit(1)
		}
		defer outputFile.Close()
	}

	var outputMu sync.Mutex

	sem := make(chan struct{}, *flagWorkers)
	var wg sync.WaitGroup

	for _, key := range keys {
		wg.Add(1)
		sem <- struct{}{}
		go func(k string) {
			defer wg.Done()
			defer func() { <-sem }()
			kr := validateKey(k, *flagProject, checks)

			if jsonlFile != nil {
				data, err := json.Marshal(kr)
				if err == nil {
					outputMu.Lock()
					jsonlFile.Write(data)
					jsonlFile.Write([]byte("\n"))
					outputMu.Unlock()
				}
			}

			if outputFile != nil {
				var vulns []string
				for _, r := range kr.Results {
					if r.Status == StatusVulnerable {
						vulns = append(vulns, r.Category+"/"+r.Service+" — "+r.Detail)
					}
				}
				if len(vulns) > 0 {
					outputMu.Lock()
					fmt.Fprintf(outputFile, "%s\n", k)
					for _, v := range vulns {
						fmt.Fprintf(outputFile, "  %s\n", v)
					}
					fmt.Fprintln(outputFile)
					outputMu.Unlock()
				}
			}
		}(key)
	}
	wg.Wait()
}
