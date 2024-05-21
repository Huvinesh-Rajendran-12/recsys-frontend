package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Templates struct {
    templates *template.Template
}

type Secret struct {
    ID       int    `json:"id"`
    Title    string `json:"name"`
    Secret   string `json:"secret"`
    SecretID string `json:"secretID"`
}

type SecretsResponse struct {
    Secrets []Secret `json:"secrets"`
}

type Recommendation struct {
    Description string  `json:"description"`
    Name        string  `json:"name"`
    Price       string  `json:"price"`
    Score       float64 `json:"score"`
}

type ProductRecommendations struct {
    Recommendations []Recommendation `json:"recommendations"`
}

type Product struct {
    Allergens   string `json:"allergens"`
    Description string `json:"description"`
    Gender      string `json:"gender"`
    ID          int    `json:"id"`
    Name        string `json:"name"`
    Price       string `json:"price"`
}

type ProductData struct {
    Products []Product `json:"products"`
}

type Affiliation struct {
    ID   int    `json:"id"`
    Name string `json:"name"`
}

type Affiliations struct {
    Data []Affiliation `json:"affiliations"` // Note the slice of Affiliation structs
}

type ProductPage struct {
    Data *ProductData
    FormData *ProductFormData
}

type ProductFormData struct {
    Values map[string]string
    Errors map[string]string
}

type APIPage struct {
    Data *SecretsResponse
    FormData *SecretFormData
}

type SecretFormData struct {
    Values map[string]string
    Errors map[string]string
}

type Data struct {
    Recommendations []Recommendation
    Rec_count int
}

type Page struct {
    Data *Data
    FormData *FormData
}

type FormData struct {
    Values map[string]string
    Errors map[string]string
    LimitOptions []int
    AffiliationOptions Affiliations
}

func (t *Templates) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
    return t.templates.ExecuteTemplate(w, name, data)
}


func initRecData() *Data {
    return &Data{
        Recommendations: []Recommendation{},
        Rec_count: 0,
    }
}

func newRecFormData() *FormData {
    affiliationsData, err := getAffiliations()
    if err != nil {
        log.Printf("Error getting Affiliations: %v", err)
    }
    return &FormData{
        Values: make(map[string]string),
        Errors: make(map[string]string),
        LimitOptions: []int{5, 10, 20, 50},
        AffiliationOptions: affiliationsData,
    }
}


func initRecPage() *Page {
    return &Page{
        Data: initRecData(),
        FormData: newRecFormData(),
    }
}

func initProdPage() *ProductPage {
    products, err := getProdData()
    if err != nil {
        log.Printf("Error getting ProductData: %v", err)
    }
    return &ProductPage{
        Data: &ProductData{
            Products: products,
        },
        FormData: &ProductFormData{
            Values: make(map[string]string),
            Errors: make(map[string]string),
        },
    }
}

func initAPIPage() *APIPage {
    secrets, err := getSecrets()
    if err != nil {
        log.Fatal(err)
    }
    return &APIPage{
        Data: &SecretsResponse{
            Secrets: secrets,
        },
        FormData: &SecretFormData{
            Values: make(map[string]string),
            Errors: make(map[string]string),
        }, 
    }
}

func getRecommendations(query string, userId int, affiliationId int,  limit int) ProductRecommendations {
    err := godotenv.Load() // Load .env file
    if err != nil {
        log.Fatal(err)
    }

    // Access environment variables
    uri := os.Getenv("URI")

    // Create a JSON payload
    payload := struct {
        Query  string `json:"query"`
        UserId int    `json:"user_id"`
        AffiliationId int `json:"affiliation_id"`
        Limit  int    `json:"limit"`
    }{
        Query:  query,
        UserId: userId,
        AffiliationId: affiliationId,
        Limit:  limit,
    }

    // Marshal the payload to JSON
    jsonPayload, err := json.Marshal(payload)
    if err != nil {
        log.Println("Error marshaling JSON payload:", err)
        return ProductRecommendations{}
    }

    // Create a new HTTP request
    req, err := http.NewRequest("GET", uri, bytes.NewBuffer(jsonPayload))
    if err != nil {
        log.Println("Error creating HTTP request:", err)
        return ProductRecommendations{}
    }

    // Set the Content-Type header to application/json
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcnlUaW1lIjoxNzE0OTg2MzgyLCJzZWNyZXRfaWQiOiJLbHd5N2xicmFFU1FiNGdxS085MDVKM0VadVpzQVBjSiIsInNlY3JldF9rZXkiOiJsVGlUMkVWWkRQZzY5U1hIcGlVMjlraVkzckdmdlRLMCJ9.4ENfOAtz1xTBPp5wn3FRUTGHZxS6KvIY9ayvQDyYqu8")

    // Make the HTTP request
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Println("Error making API request:", err)
        return ProductRecommendations{}
    }
    defer resp.Body.Close()
    // Decode JSON response
    var prodRec ProductRecommendations
    err = json.NewDecoder(resp.Body).Decode(&prodRec)
    if err != nil {
        log.Println("Error decoding JSON response:", err)
        return ProductRecommendations{}
    }
    return prodRec
}

func getProdData() ([]Product, error) {
    err := godotenv.Load() // Load .env file
    if err != nil {
        log.Fatal(err)
    }

    // Access environment variables
    uri := os.Getenv("GET_PROD_URI")
    // connect to api
    req, err := http.NewRequest("GET", uri, nil)
    if err != nil {
        log.Println("Error creating HTTP request:", err)
        return nil, err
    }
    // Set the Content-Type header to application/json
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcnlUaW1lIjoxNzE0OTg2MzgyLCJzZWNyZXRfaWQiOiJLbHd5N2xicmFFU1FiNGdxS085MDVKM0VadVpzQVBjSiIsInNlY3JldF9rZXkiOiJsVGlUMkVWWkRQZzY5U1hIcGlVMjlraVkzckdmdlRLMCJ9.4ENfOAtz1xTBPp5wn3FRUTGHZxS6KvIY9ayvQDyYqu8")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Println("Error making API request:", err)
        return nil, err
    }
    defer resp.Body.Close()
    var prodData ProductData
    err = json.NewDecoder(resp.Body).Decode(&prodData)
    if err != nil {
        log.Println("Error decoding JSON response:", err)
        return nil, err
    }
    return prodData.Products, nil
}

func getAffiliations() (Affiliations, error) {
    err := godotenv.Load() // Load .env file
    if err != nil {
        log.Fatal(err)
    }

    // Access environment variables
    uri := os.Getenv("GET_AFFILIATION_URI")

    // connect to api
    req, err := http.NewRequest("GET", uri, nil)
    if err != nil {
        log.Println("Error creating HTTP request:", err)
        return Affiliations{}, err
    }
    req.Header.Set("Content-Type", "application/json") // Set content type

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Println("Error making API request:", err)
        return Affiliations{}, err
    }
    defer resp.Body.Close()

    // Read the response body
    body, err := io.ReadAll(resp.Body) // Read body before decoding
    if err != nil {
        log.Println("Error reading response body:", err)
        return Affiliations{}, err
    }

    // Print the response body for debugging
    var affiliationsData Affiliations

    // Decode the JSON (reset the response body for decoding)
    err = json.NewDecoder(bytes.NewReader(body)).Decode(&affiliationsData) // Decode from a new reader
    if err != nil {
        log.Println("Error decoding JSON response:", err)
        return Affiliations{}, err
    }

    return affiliationsData, nil
}

func addProductData(product Product) {
    err := godotenv.Load() // Load .env file
    if err != nil {
        log.Fatal(err)
    }

    uri := os.Getenv("ADD_PROD_URI")
    url := fmt.Sprintf("%s", uri)
    jsonBody, err := json.Marshal(product)
    if err != nil {
        log.Fatal(err)
    }
    resp, err := http.Post(url, "application/json", bytes.NewReader(jsonBody))
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()
}

func editProductData(product Product) {
    err := godotenv.Load() // Load .env file
    if err != nil {
        log.Fatal(err)
    }

    uri := os.Getenv("EDIT_PROD_URI")
    url := fmt.Sprintf("%s", uri)
    jsonBody, err := json.Marshal(product)
    if err != nil {
        log.Fatal(err)
    }
    resp, err := http.Post(url, "application/json", bytes.NewReader(jsonBody))
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()
}

func generateSecrets(title string) error {
    err := godotenv.Load() // Load .env file
    if err != nil {
        log.Fatal(err)
        return err
    }

    uri := os.Getenv("GENERATE_SECRET_URI")
    log.Println(uri)
    payload := struct {
        Title string `json:"title"`
    }{
        Title:  title,
    }
    jsonBody, err := json.Marshal(payload)
    if err != nil {
        log.Fatal(err)
    }
    resp, err := http.Post(uri, "application/json", bytes.NewReader(jsonBody))
    if err != nil {
        log.Fatal(err)
        return err
    }
    defer resp.Body.Close()
    return nil
}

func getSecrets() ([]Secret, error) { // Update return type
    err := godotenv.Load()
    if err != nil {
        log.Fatal(err)
    }

    uri := os.Getenv("GET_SECRETS_URI")

    req, err := http.NewRequest("GET", uri, nil)
    if err != nil {
        log.Println("Error creating HTTP request:", err)
        return []Secret{}, err
    }
    // Set the Content-Type header to application/json
    req.Header.Set("Content-Type", "application/json")
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Println("Error making API request:", err)
        return []Secret{}, err
    }
    defer resp.Body.Close()

    // Decode the SecretResponse
    var secretResponse SecretsResponse 
    err = json.NewDecoder(resp.Body).Decode(&secretResponse)
    if err != nil {
        log.Println("Error decoding JSON response:", err)
        return nil, err // Return error and empty slice
    }

    return secretResponse.Secrets, nil // Return secrets and no error
}

func Authentication(username string, password string) (bool, error) {
    err := godotenv.Load() // Load .env file
    if err != nil {
        log.Fatal(err)
    }

    // Access environment variables
    uri := os.Getenv("AUTHENTICATION_URI")

    // Create a JSON payload
    payload := struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }{
        Username: username,
        Password: password,
    }
    var authenticationResult struct {
        Authentication bool `json:"authenticated"`
    }

    // Marshal the payload to JSON
    jsonPayload, err := json.Marshal(payload)
    if err != nil {
        log.Println("Error marshaling JSON payload:", err)
        return false, err
    }
    // Create a new HTTP request
    req, err := http.NewRequest("POST", uri, bytes.NewBuffer(jsonPayload))
    if err != nil {
        log.Println("Error creating HTTP request:", err)
        return false, err
    }

    // Set the Content-Type header to application/json
    req.Header.Set("Content-Type", "application/json")

    // Make the HTTP request
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Println("Error making API request:", err)
        return false, err
    }
    defer resp.Body.Close()
    err = json.NewDecoder(resp.Body).Decode(&authenticationResult)
    if err != nil {
        log.Println("Error decoding JSON response:", err)
        return false, err
    }
    log.Println("Authentication result:", authenticationResult.Authentication)
    return authenticationResult.Authentication, nil
}

func IsAuthenticated(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        sess, _ := session.Get("session", c)
        isauthenticated, ok := sess.Values["authenticated"]
        if !ok {
            return c.Redirect(http.StatusMovedPermanently, "/login")
        }
        log.Println("IsAuthenticated", isauthenticated)
        c.Set("authenticated", isauthenticated)
        return next(c)
    }
}

func NewTemplate() *Templates {
    return &Templates{
        templates: template.Must(template.ParseGlob("views/*.html")),
    }
}

func main() {
    e := echo.New()
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())
    page := initRecPage()
    prodPage := initProdPage()
    apiPage := initAPIPage()
    e.Renderer = NewTemplate()
    var (
        // key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
        key = []byte(os.Getenv("SESSION_KEY"))
        store = sessions.NewCookieStore(key)
    )

    store.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   86400 * 30, // 30 days
        HttpOnly: true,
        Secure:   false, // Set to true if using HTTPS
    }

    sessionMiddleware := session.Middleware(store)
    e.Use(sessionMiddleware)

    e.GET("/login", func(c echo.Context) error {
        return c.Render(http.StatusOK, "loginPage", nil)
    })
    e.POST("/login", func(c echo.Context) error {
        username := c.FormValue("username")
        password := c.FormValue("password")

        // Check if the user exists and verify the password
        isAuthenticated, err := Authentication(username, password)
        if err != nil {
            log.Printf("Authentication failed: %v", err)
        }

        if isAuthenticated {
            // Create a session and store the user ID
            sess, _ := session.Get("session", c)
            sess.Values["authenticated"] = true
            sess.Save(c.Request(), c.Response())
            log.Println("Successfully authenticated")

            if c.Request().Header.Get("HX-Request") == "true" {
                // HTMX request, send HX-Redirect header
                c.Response().Header().Set("HX-Redirect", "/dashboard")
                return c.NoContent(http.StatusOK)
            }
            return c.Redirect(http.StatusSeeOther, "/dashboard")
        } else {
            errMsg := "Invalid username or password"
            if c.Request().Header.Get("HX-Request") == "true" {
                // HTMX request, return login form with error message
                return c.Render(http.StatusUnauthorized, "loginPage", map[string]interface{}{
                    "error": errMsg,
                })
            }
            return c.Redirect(http.StatusUnauthorized, "/login?error="+errMsg)
        }
    })
    e.GET("/logout", func(c echo.Context) error {
        sess, _ := session.Get("session", c)
        sess.Values["authenticated"] = false
        sess.Options.MaxAge = -1 // This will delete the session
        err := sess.Save(c.Request(), c.Response())
        if err != nil {
            log.Println("Error saving session:", err)
            return c.NoContent(http.StatusInternalServerError)
        }
        return c.Redirect(http.StatusSeeOther, "/login")
    })

    e.GET("/", IsAuthenticated(func(c echo.Context) error {
        return c.Redirect(http.StatusMovedPermanently, "/dashboard")
    }))

    e.GET("/dashboard", IsAuthenticated(func(c echo.Context) error {
        return c.Render(http.StatusOK, "index", page)
    }))

    e.GET("/products", IsAuthenticated(func(c echo.Context) error {
        return c.Render(http.StatusOK, "productPage", prodPage)
    }))

    e.POST("/recommend", IsAuthenticated(func (c echo.Context) error {
        query := c.FormValue("query")
        userId, err := strconv.Atoi(c.FormValue("userId"))
        if err != nil {
            formData := newRecFormData()
            formData.Errors["userId"] = "User ID cannot be empty"
            if c.Request().Header.Get("HX-Request") == "true" {
                return c.Render(http.StatusUnprocessableEntity, "form", formData)
            }
            return c.Render(http.StatusUnprocessableEntity, "index", page)
        }
        limit, err := strconv.Atoi(c.FormValue("limit"))
        if err != nil {
            formData := newRecFormData()
            if c.Request().Header.Get("HX-Request") == "true" {
                return c.Render(http.StatusBadRequest, "form", formData)
            }
            return c.Render(http.StatusBadRequest, "index", page)
        }
        affiliationId, err := strconv.Atoi(c.FormValue("affiliationId"))
        if err != nil {
            formData := newRecFormData()
            if c.Request().Header.Get("HX-Request") == "true" {
                return c.Render(http.StatusBadRequest, "form", formData)
            }
            return c.Render(http.StatusBadRequest, "index", page)
        }
        prodRec := getRecommendations(query, userId, affiliationId, limit)
        if len(prodRec.Recommendations) == 0 {
            formData := newRecFormData()
            if c.Request().Header.Get("HX-Request") == "true" {
                return c.Render(http.StatusBadRequest, "form", formData)
            }
            return c.Render(http.StatusBadRequest, "index", page)
        }
        page.Data.Recommendations = prodRec.Recommendations
        page.Data.Rec_count = len(prodRec.Recommendations)
        c.Render(http.StatusOK, "form", page.FormData)
        return c.Render(http.StatusOK, "recommendations", page.Data)
    }))

    e.GET("/manage/api", IsAuthenticated(func (c echo.Context) error {
        return c.Render(http.StatusOK, "apiDashboard", apiPage.Data)
    }))

    e.POST("/products/add", func(c echo.Context) error {
        product := Product{
            Name:        c.FormValue("name"),
            Description: c.FormValue("description"),
            Price:       c.FormValue("price"),
            Allergens:   c.FormValue("allergens"),
            Gender:      c.FormValue("gender"),
        }
        addProductData(product)
        products, err := getProdData()
        if err != nil {
            log.Printf("Error getting ProductData: %v", err)
        }
        prodPage.Data.Products = products
        c.Render(http.StatusOK, "productForm", prodPage.FormData)
        return c.Render(http.StatusOK, "productPage", prodPage.Data)
    })

    e.GET("/products/edit", IsAuthenticated(func(c echo.Context) error {
        idStr := c.QueryParam("id")
        id, err := strconv.Atoi(idStr)
        if err != nil {
            return err
        }

        var product Product
        for _, p := range prodPage.Data.Products {
            if p.ID == id {
                product = p
                break
            }
        }

        //Render the product data to an editable form within the row
        return c.Render(http.StatusOK, "editableProductRow", product)
    }))

    e.PUT("/products/edit", func(c echo.Context) error {
        id, err := strconv.Atoi(c.FormValue("id"))
        if err != nil {
            log.Fatal(err)
        }
        product := Product{
            ID:          id,
            Name:        c.FormValue("name"),
            Description: c.FormValue("description"),
            Price:       c.FormValue("price"),
            Allergens:   c.FormValue("allergens"),
            Gender:      c.FormValue("gender"),
        }
        editProductData(product)
        products, err := getProdData()
        if err != nil {
            log.Printf("Error getting ProductData: %v", err)
        }
        prodPage.Data.Products = products
        c.Render(http.StatusOK, "productForm", prodPage.FormData)
        return c.Render(http.StatusOK, "productPage", prodPage.Data)
    })
    e.POST("/secrets/generate", func(c echo.Context) error {
        title := c.FormValue("title")

        // Generate secrets and handle potential errors
        if err := generateSecrets(title); err != nil {
            log.Printf("Error generating secrets: %v", err)
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate secrets"})
        }

        // Retrieve secrets and handle potential errors
        secrets, err := getSecrets()
        if err != nil {
            log.Printf("Error getting secrets: %v", err)
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve secrets"})
        }

        // Render the table template with just the secrets data
        return c.Render(http.StatusOK, "apiDashboardTable", secrets)
    })
    e.Logger.Fatal(e.Start(":8081"))
    
}
