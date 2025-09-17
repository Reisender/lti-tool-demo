package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Reisender/lti-tool-demo/components"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
)

//go:generate templ generate

// Configuration for LTI Tool
type Config struct {
	Issuer             string
	ClientID           string
	AuthLoginURL       string
	AuthTokenURL       string
	KeyID              string
	PrivateKey         *rsa.PrivateKey
	PublicKeyJWK       map[string]interface{}
	SessionStore       *sessions.CookieStore
	LaunchValidityMins int
}

// Global configuration
var config Config

// Store nonces to prevent replay attacks
var nonceStore = make(map[string]time.Time)

// Initialize the configuration and generate keys if needed
func initConfig() error {
	// Try to load environment variables
	godotenv.Load()

	// Set up session store with random key
	randomKey := make([]byte, 32)
	_, err := rand.Read(randomKey)
	if err != nil {
		return err
	}
	config.SessionStore = sessions.NewCookieStore(randomKey)

	// Generate RSA key pair if not already available
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	config.PrivateKey = privateKey

	// Create JWK from public key
	config.PublicKeyJWK = map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": "lti-tool-key",
		"n":   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // e=65537
	}

	config.KeyID = "lti-tool-key"
	config.LaunchValidityMins = 5

	// Default dummy values - in production these should come from env vars
	config.Issuer = os.Getenv("LTI_ISSUER")
	if config.Issuer == "" {
		// Use LTI_BASE_URL if available, otherwise fall back to a default localhost URL
		baseURL := os.Getenv("LTI_BASE_URL")
		if baseURL == "" {
			port := os.Getenv("PORT")
			if port == "" {
				port = "8088"
			}
			baseURL = fmt.Sprintf("http://localhost:%s", port)
		}
		config.Issuer = baseURL
	}

	config.ClientID = os.Getenv("LTI_CLIENT_ID")
	if config.ClientID == "" {
		config.ClientID = "lti-tool-client-id"
	}

	return nil
}

// Handler for the tool configuration
func configHandler(w http.ResponseWriter, r *http.Request) {
	// Canvas expects XML format for the configuration
	xmlConfig := `<?xml version="1.0" encoding="UTF-8"?>
<cartridge_basiclti_link xmlns="http://www.imsglobal.org/xsd/imslticc_v1p0"
    xmlns:blti = "http://www.imsglobal.org/xsd/imsbasiclti_v1p0"
    xmlns:lticm ="http://www.imsglobal.org/xsd/imslticm_v1p0"
    xmlns:lticp ="http://www.imsglobal.org/xsd/imslticp_v1p0"
    xmlns:xsi = "http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation = "http://www.imsglobal.org/xsd/imslticc_v1p0 http://www.imsglobal.org/xsd/lti/ltiv1p0/imslticc_v1p0.xsd
    http://www.imsglobal.org/xsd/imsbasiclti_v1p0 http://www.imsglobal.org/xsd/lti/ltiv1p0/imsbasiclti_v1p0.xsd
    http://www.imsglobal.org/xsd/imslticm_v1p0 http://www.imsglobal.org/xsd/lti/ltiv1p0/imslticm_v1p0.xsd
    http://www.imsglobal.org/xsd/imslticp_v1p0 http://www.imsglobal.org/xsd/lti/ltiv1p0/imslticp_v1p0.xsd">
    <blti:title>Ednition LTI Tool</blti:title>
    <blti:description>Ednition LTI Tool for educational enhancement</blti:description>
    <blti:launch_url>` + fmt.Sprintf("%s/lti/launch", config.Issuer) + `</blti:launch_url>
    <blti:icon>` + fmt.Sprintf("%s/static/ednition-logo.svg", config.Issuer) + `</blti:icon>
    <blti:extensions platform="canvas.instructure.com">
        <lticm:property name="tool_id">ednition-lti-tool</lticm:property>
        <lticm:property name="privacy_level">public</lticm:property>
        <lticm:property name="domain">` + getDomainFromURL(config.Issuer) + `</lticm:property>
        <lticm:property name="text">Ednition LTI Tool</lticm:property>
        <lticm:property name="selection_width">800</lticm:property>
        <lticm:property name="selection_height">600</lticm:property>
        <lticm:options name="course_navigation">
            <lticm:property name="url">` + fmt.Sprintf("%s/lti/launch", config.Issuer) + `</lticm:property>
            <lticm:property name="enabled">true</lticm:property>
            <lticm:property name="text">Ednition LTI Tool</lticm:property>
            <lticm:property name="default">enabled</lticm:property>
            <lticm:property name="visibility">public</lticm:property>
            <lticm:property name="display_type">full_width</lticm:property>
            <lticm:property name="canvas_icon_class">icon-lti</lticm:property>
            <lticm:property name="icon_url">` + fmt.Sprintf("%s/static/ednition-logo.svg", config.Issuer) + `</lticm:property>
            <lticm:property name="windowTarget">_self</lticm:property>
        </lticm:options>
        <lticm:options name="assignment_selection">
            <lticm:property name="url">` + fmt.Sprintf("%s/lti/launch", config.Issuer) + `</lticm:property>
            <lticm:property name="enabled">true</lticm:property>
            <lticm:property name="text">Ednition LTI Tool</lticm:property>
        </lticm:options>
        <lticm:options name="link_selection">
            <lticm:property name="url">` + fmt.Sprintf("%s/lti/launch", config.Issuer) + `</lticm:property>
            <lticm:property name="enabled">true</lticm:property>
            <lticm:property name="text">Ednition LTI Tool</lticm:property>
        </lticm:options>
        <lticm:options name="editor_button">
            <lticm:property name="url">` + fmt.Sprintf("%s/lti/launch", config.Issuer) + `</lticm:property>
            <lticm:property name="enabled">true</lticm:property>
            <lticm:property name="icon_url">` + fmt.Sprintf("%s/static/ednition-logo.svg", config.Issuer) + `</lticm:property>
            <lticm:property name="text">Ednition LTI Tool</lticm:property>
            <lticm:property name="selection_width">800</lticm:property>
            <lticm:property name="selection_height">600</lticm:property>
        </lticm:options>
    </blti:extensions>
    <cartridge_bundle identifierref="BLTI001_Bundle"/>
    <cartridge_icon identifierref="BLTI001_Icon"/>
</cartridge_basiclti_link>`

	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(xmlConfig))
}

// Helper function to extract domain from URL
func getDomainFromURL(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Also add a JSON configuration endpoint for non-Canvas LMS
func jsonConfigHandler(w http.ResponseWriter, r *http.Request) {
	toolConfig := map[string]interface{}{
		"title":               "LTI Tool Demo",
		"description":         "A simple LTI 1.3 Tool demo",
		"oidc_initiation_url": fmt.Sprintf("%s/lti/login", config.Issuer),
		"target_link_uri":     fmt.Sprintf("%s/lti/launch", config.Issuer),
		"scopes":              []string{"openid"},
		"claims":              []string{"sub", "iss", "name", "given_name", "family_name", "email"},
		"public_jwk_url":      fmt.Sprintf("%s/lti/jwks", config.Issuer),
		"custom_fields":       map[string]string{},
		"extensions":          []map[string]interface{}{},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toolConfig)
}

// Handler for JWKS (JSON Web Key Set)
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			config.PublicKeyJWK,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// Handler for OIDC login initiation
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Get parameters from the login request
	issuer := r.Form.Get("iss")
	clientID := r.Form.Get("client_id")
	loginHint := r.Form.Get("login_hint")
	targetLinkURI := r.Form.Get("target_link_uri")
	ltiMessageHint := r.Form.Get("lti_message_hint")

	if issuer == "" || clientID == "" || targetLinkURI == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Create a new session to store launch data
	session, _ := config.SessionStore.New(r, "lti-session")

	// Generate state and nonce
	state := uuid.New().String()
	nonce := uuid.New().String()

	// Store in session
	session.Values["state"] = state
	session.Values["nonce"] = nonce
	session.Values["target_link_uri"] = targetLinkURI

	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Store nonce for later validation
	nonceStore[nonce] = time.Now().Add(time.Duration(config.LaunchValidityMins) * time.Minute)

	// Build auth redirect URL
	authURL := fmt.Sprintf("%s?scope=openid&response_type=id_token&client_id=%s&redirect_uri=%s&login_hint=%s&state=%s&nonce=%s&prompt=none&response_mode=form_post&lti_message_hint=%s",
		issuer, clientID, targetLinkURI, loginHint, state, nonce, ltiMessageHint)

	// Redirect to authentication URL
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Handler for LTI launch
func launchHandler(w http.ResponseWriter, r *http.Request) {
	// Parse form data first to ensure we can access all POST data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Log all form data for debugging
	log.Printf("LTI Launch - Form POST data:")
	for key, values := range r.Form {
		log.Printf("  %s: %v", key, values)
	}

	// Check if this is a direct access (course navigation) or a proper LTI launch
	idToken := r.FormValue("id_token")
	if idToken == "" {
		// This could be a direct access from course navigation
		// In this case, we'll show a simplified welcome page
		log.Println("Direct access detected (no ID token) - likely from course navigation")

		// For course navigation, we'll create a generic welcome
		formData := make(map[string]interface{})
		for key, values := range r.Form {
			if len(values) == 1 {
				formData[key] = values[0]
			} else {
				formData[key] = values
			}
		}

		data := components.WelcomeData{
			Name: "Canvas User",
			Role: "Course Navigation",
			LaunchInfo: map[string]interface{}{
				"note":     "This is a direct access without an LTI launch token",
				"formData": formData,
			},
		}

		err := components.WelcomeView(data).Render(r.Context(), w)
		if err != nil {
			http.Error(w, "Error rendering welcome page: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Normal LTI launch flow for POST requests with ID token
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("Received LTI launch with ID token: %s", idToken)

	// Parse and validate the token
	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// In a real implementation, you'd verify the issuer's key
		// For this demo, we're just returning a dummy key
		return &rsa.PublicKey{}, nil
	})

	if err != nil {
		log.Printf("Failed to parse token: %v", err)
		http.Error(w, "Failed to parse token: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get claims from token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	// Log all claims for debugging
	log.Printf("LTI Launch Claims: %+v", claims)

	// Create formatted JSON string of all claims
	claimsJSON, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		log.Printf("Error formatting claims as JSON: %v", err)
	}
	log.Printf("Claims as formatted JSON:\n%s", string(claimsJSON))

	// Extract user info from claims
	name := claims["name"]
	role := "Unknown"
	if roles, ok := claims["https://purl.imsglobal.org/spec/lti/claim/roles"].([]interface{}); ok && len(roles) > 0 {
		role = roles[0].(string)
	}

	// Add form data to the launch info
	formData := make(map[string]interface{})
	for key, values := range r.Form {
		if len(values) == 1 {
			formData[key] = values[0]
		} else {
			formData[key] = values
		}
	}

	launchInfo := make(map[string]interface{})
	for k, v := range claims {
		launchInfo[k] = v
	}
	launchInfo["formData"] = formData

	// Use our Templ component instead of the HTML template
	data := components.WelcomeData{
		Name:       fmt.Sprintf("%v", name),
		Role:       fmt.Sprintf("%v", role),
		LaunchInfo: launchInfo,
	}

	// Render the welcome page using Templ
	err = components.WelcomeView(data).Render(r.Context(), w)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
	}
}

// Simple API endpoint for HTMX demo using Templ
func greetingHandler(w http.ResponseWriter, r *http.Request) {
	err := components.GreetingComponent().Render(r.Context(), w)
	if err != nil {
		http.Error(w, "Error rendering component: "+err.Error(), http.StatusInternalServerError)
	}
}

// Save the private key to a file (for demo purposes)
func savePrivateKey() error {
	// Create a PEM block for the private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(config.PrivateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Write to file
	return os.WriteFile("private_key.pem", privateKeyPEM, 0600)
}

// Handler for the root path
func homeHandler(w http.ResponseWriter, r *http.Request) {
	err := components.HomePage().Render(r.Context(), w)
	if err != nil {
		http.Error(w, "Error rendering home page: "+err.Error(), http.StatusInternalServerError)
	}
}

// Handler to provide the configuration URL
func configURLHandler(w http.ResponseWriter, r *http.Request) {
	configURL := fmt.Sprintf("%s/lti/config", config.Issuer)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(configURL))
}

// Handler for serving CSS directly
func cssHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("CSS handler called for %s", r.URL.Path)
	cssPath := "static/ednition.css"

	// Check if file exists
	_, err := os.Stat(cssPath)
	if os.IsNotExist(err) {
		log.Printf("CSS file not found at %s", cssPath)
		http.Error(w, "CSS file not found", http.StatusNotFound)
		return
	}

	cssContent, err := os.ReadFile(cssPath)
	if err != nil {
		log.Printf("Error reading CSS file: %v", err)
		http.Error(w, "Error reading CSS file", http.StatusInternalServerError)
		return
	}

	// Set appropriate headers BEFORE writing any content
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	log.Printf("Serving CSS file with Content-Type: %s", w.Header().Get("Content-Type"))

	w.WriteHeader(http.StatusOK) // explicitly set status code
	_, err = w.Write(cssContent)
	if err != nil {
		log.Printf("Error writing CSS content: %v", err)
	}
}

func main() {
	if err := initConfig(); err != nil {
		log.Fatalf("Failed to initialize configuration: %v", err)
	}

	// Save private key for reference
	if err := savePrivateKey(); err != nil {
		log.Printf("Failed to save private key: %v", err)
	}

	// Print configuration URL
	fmt.Printf("LTI Configuration URL: %s/lti/config\n", config.Issuer)
	fmt.Println("You can use this URL to configure the LTI tool in your LMS.")
	fmt.Println("Note: In a production environment, you need to ensure the Issuer URL matches your domain.")

	// Set up routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/lti/config", configHandler)
	http.HandleFunc("/lti/config.json", jsonConfigHandler)
	http.HandleFunc("/lti/jwks", jwksHandler)
	http.HandleFunc("/lti/login", loginHandler)
	http.HandleFunc("/lti/launch", launchHandler)
	http.HandleFunc("/api/greeting", greetingHandler)
	http.HandleFunc("/api/config-url", configURLHandler)
	http.HandleFunc("/css/ednition.css", cssHandler)

	// Serve static files if needed
	http.Handle("/static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Debug logging
		log.Printf("Static file requested: %s", r.URL.Path)

		// Add security and CORS headers for iframe compatibility
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Force Content-Type for known file extensions
		if strings.HasSuffix(r.URL.Path, ".css") {
			log.Printf("Setting Content-Type to text/css for: %s", r.URL.Path)
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		} else if strings.HasSuffix(r.URL.Path, ".svg") {
			w.Header().Set("Content-Type", "image/svg+xml")
		} else if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		} else if strings.HasSuffix(r.URL.Path, ".html") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		} else if strings.HasSuffix(r.URL.Path, ".png") {
			w.Header().Set("Content-Type", "image/png")
		}

		// Disable caching for development
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		// Check if file exists before serving
		filePath := "static/" + r.URL.Path
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			log.Printf("File not found: %s", filePath)
			http.NotFound(w, r)
			return
		}

		http.FileServer(http.Dir("static")).ServeHTTP(w, r)
	})))

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8088"
	}
	fmt.Printf("Starting LTI Tool on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
