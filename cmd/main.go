package main

import (
    "bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
    "os"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
    "log"
    "github.com/joho/godotenv"
    "net/url"
)

type Templates struct {
    templates *template.Template
}

type Recommendation struct {
    Name string `json:"name"`
    Description string `json:"description"`
    Price string `json:"price"`
    Score float64 `json:"score"`
}

type Product struct {
    Name string `json:"name"`
    Description string `json:"description"`
    Price string `json:"price"`
    Allergen string `json:"allergens"`
    Gender string `json:"gender"`
}

type ProductData struct {
    Products []Product
    Product_count int
}

type ProductPage struct {
    Data *ProductData
    FormData *ProductFormData
}

type ProductFormData struct {
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
}

func (t *Templates) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
    return t.templates.ExecuteTemplate(w, name, data)
}

func initProdData() *ProductData {
    products := getProdData()
    return &ProductData{
        Products: products, 
        Product_count: len(products),
    }
}


func initRecData() *Data {
    return &Data{
        Recommendations: []Recommendation{}, 
        Rec_count: 0,
    }
}

func newRecFormData() *FormData {
    return &FormData{
        Values : make(map[string]string),
        Errors : make(map[string]string),
        LimitOptions: []int{5, 10, 20, 50},
    }
}

func newProdFormData() *ProductFormData {
    return &ProductFormData{
        Values : make(map[string]string),
        Errors : make(map[string]string),
    }
}

func initRecPage() *Page {
    return &Page{
        Data: initRecData(),
        FormData: newRecFormData(),
    } 
}

func initProdPage() *ProductPage {
    return &ProductPage{
        Data: initProdData(),
        FormData: newProdFormData(),
    } 
}

func getRecommendations(query string, userId int, limit int) []Recommendation {
    err := godotenv.Load() // Load .env file
    if err != nil {
        log.Fatal(err)
    }

    // Access environment variables
    queryStr := url.QueryEscape(query)
    fmt.Println(queryStr)
    uri := os.Getenv("URI")
    url := fmt.Sprintf("%s?query=%s&userId=%d&limit=%d", uri, queryStr, userId, limit)
    fmt.Println(url)
    // connect to api
    resp, err := http.Get(url)
    if err != nil {
        log.Println("Error making API request:", err)
        return []Recommendation{}
    }
    defer resp.Body.Close()
    // read the response body
    

    // Decode JSON response
    var recommendations []Recommendation
    err = json.NewDecoder(resp.Body).Decode(&recommendations)
    if err != nil {
        log.Println("Error decoding JSON response:", err)
        return []Recommendation{}
    }
    return recommendations
    
}

func getProdData() []Product {
    err := godotenv.Load() // Load .env file
    if err != nil {
        log.Fatal(err)
    }

    // Access environment variables
    uri := os.Getenv("GET_PROD_URI")
    fmt.Println(uri)
    url := fmt.Sprintf("%s", uri)
    fmt.Println(url)
    // connect to api
    resp, err := http.Get(url)
    if err != nil {
        log.Println("Error making API request:", err)
        return []Product{}
    }
    defer resp.Body.Close()
    // read the response body
    

    // Decode JSON response
    var products []Product
    err = json.NewDecoder(resp.Body).Decode(&products)
    if err != nil {
        log.Println("Error decoding JSON response:", err)
        return []Product{}
    }
    return products
}

func addProductData(product Product) {
    err := godotenv.Load() // Load .env file
    if err != nil {
        log.Fatal(err)
    }

    uri := os.Getenv("ADD_PROD_URI")
    url := fmt.Sprintf("%s", uri)
    jsonBody , err := json.Marshal(product)
    if err != nil {
        log.Fatal(err)
    }
    resp, err := http.Post(url, "application/json", bytes.NewReader(jsonBody))
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()
}

func NewTemplate() *Templates {
    return &Templates{
        templates: template.Must(template.ParseGlob("views/*.html")),
    }
}


func main(){
    e := echo.New()
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())
    page := initRecPage()
    prodPage := initProdPage()
    e.Renderer = NewTemplate() 

    e.GET("/", func(c echo.Context) error {
        return c.Render(200, "index", page)
    })

    fmt.Println(prodPage.Data.Products)
    e.GET("/products", func(c echo.Context) error {
        return c.Render(200, "productPage", prodPage)
    })

    e.POST("/recommend", func(c echo.Context) error {
        query := c.FormValue("query")
        userId , err := strconv.Atoi(c.FormValue("userId"))
        if err != nil {
            formData := newRecFormData()
            formData.Errors["userId"] = "User ID cannot be empty"
            return c.Render(422, "form", formData)
        }
        limit , err:= strconv.Atoi(c.FormValue("limit"))
        if err !=  nil {
            formData := newRecFormData()
            return c.Render(400, "form", formData)
        }
        recommendations := getRecommendations(query, userId, limit)
        fmt.Println(recommendations)
        fmt.Println(len(recommendations))
        if len(recommendations) == 0 {
            formData := newRecFormData()
            return c.Render(400, "form", formData) 
        }
        page.Data.Recommendations= recommendations
        page.Data.Rec_count = len(recommendations)
        c.Render(200, "form", newRecFormData())
        return c.Render(200, "recommendations", page.Data) 
    })
    e.POST("/products/add", func(c echo.Context) error {
        product := Product{
            Name: c.FormValue("name"),
            Description: c.FormValue("description"),
            Price: c.FormValue("price"),
            Allergen: c.FormValue("allergens"),
            Gender: c.FormValue("gender"),
        }
        addProductData(product)
        products := getProdData()
        prodData := &ProductData{
            Products: products, 
            Product_count: len(products),
        }
        c.Render(200, "productForm", newProdFormData())
        return c.Render(200, "products", prodData)
    })
    e.Logger.Fatal(e.Start(":8081"))

} 

