package main

import (
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

func initData() *Data {
    return &Data{
        Recommendations: []Recommendation{}, 
        Rec_count: 0,
    }
}

func newFormData() *FormData {
    return &FormData{
        Values : make(map[string]string),
        Errors : make(map[string]string),
        LimitOptions: []int{5, 10, 20, 50},
    }
}

func initPage() *Page {
    return &Page{
        Data: initData(),
        FormData: newFormData(),
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

func NewTemplate() *Templates {
    return &Templates{
        templates: template.Must(template.ParseGlob("views/*.html")),
    }
}


func main(){
    e := echo.New()
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())
    page := initPage()
    e.Renderer = NewTemplate() 

    fmt.Println(page.FormData)
    e.GET("/", func(c echo.Context) error {
        return c.Render(200, "index", page)
    })

    e.POST("/recommend", func(c echo.Context) error {
        query := c.FormValue("query")
        userId , err := strconv.Atoi(c.FormValue("userId"))
        if err != nil {
            formData := newFormData()
            formData.Errors["userId"] = "User ID cannot be empty"
            return c.Render(422, "form", formData)
        }
        limit , err:= strconv.Atoi(c.FormValue("limit"))
        if err !=  nil {
            formData := newFormData()
            return c.Render(400, "form", formData)
        }
        recommendations := getRecommendations(query, userId, limit)
        fmt.Println(recommendations)
        fmt.Println(len(recommendations))
        if len(recommendations) == 0 {
            formData := newFormData()
            return c.Render(400, "form", formData) 
        }
        page.Data.Recommendations= recommendations
        page.Data.Rec_count = len(recommendations)
        c.Render(200, "form", newFormData())
        return c.Render(200, "recommendations", page.Data) 
    })
    e.Logger.Fatal(e.Start(":8081"))

} 

