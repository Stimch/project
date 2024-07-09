package main

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	oauth2api "google.golang.org/api/oauth2/v2"
)

func googleAuth(c *gin.Context) {
	conf := &oauth2.Config{
		ClientID:     "853992012810-0d0drir7d25hkfce9tbprl4squ2teepl.apps.googleusercontent.com",
		ClientSecret: "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",
		RedirectURL:  "http://localhost:8080/v1/google/callback",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	url := conf.AuthCodeURL("state")
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func getProductDates(c *gin.Context) {
	productName := c.Param("product_name")

	db, err := sql.Open("sqlite3", "./sales.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT date FROM sales WHERE product=? ORDER BY date", productName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var dates []string
	for rows.Next() {
		var date string
		err = rows.Scan(&date)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		dates = append(dates, date)
	}

	c.JSON(http.StatusOK, dates)
}

func googleCallback(c *gin.Context) {
	conf := &oauth2.Config{
		ClientID:     "853992012810-0d0drir7d25hkfce9tbprl4squ2teepl.apps.googleusercontent.com",
		ClientSecret: "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",
		RedirectURL:  "http://localhost:8080/v1/google/callback",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	code := c.Query("code")
	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	client := conf.Client(context.Background(), &oauth2.Token{AccessToken: token.AccessToken})
	oauth2Service, err := oauth2api.New(client)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	userinfo, err := oauth2Service.Userinfo.Get().Do()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": userinfo})
}

type SalesRecord struct {
	Product  string  `json:"product"`
	Quantity int     `json:"quantity"`
	Total    float64 `json:"total"`
	Date     string  `json:"date"`
}

func addSalesRecord(c *gin.Context) {
	var record SalesRecord
	if err := c.ShouldBindJSON(&record); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db, err := sql.Open("sqlite3", "./sales.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer db.Close()

	stmt, err := db.Prepare("INSERT INTO sales (product, quantity, total, date) VALUES (?, ?, ?, ?)")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(record.Product, record.Quantity, record.Total, record.Date)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Sales record added successfully"})
}

type SalesReport struct {
	Product  string  `json:"product"`
	Quantity int     `json:"quantity"`
	Total    float64 `json:"total"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func registerUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db, err := sql.Open("sqlite3", "./logs.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer db.Close()

	stmt, err := db.Prepare("INSERT INTO users (username, password) VALUES (?, ?)")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.Username, user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func loginUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db, err := sql.Open("sqlite3", "./logs.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer db.Close()

	var dbUser User
	err = db.QueryRow("SELECT username, password FROM users WHERE username=?", user.Username).Scan(&dbUser.Username, &dbUser.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	if user.Password != dbUser.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged in successfully"})
}

func getSalesReport(c *gin.Context) {
	year := c.Param("year")
	// fmt.Println("year:", year)
	month := c.Param("month")

	db, err := sql.Open("sqlite3", "./sales.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer db.Close()

	rows, err := db.Query(`SELECT product, SUM(quantity) as quantity, SUM(total) as total
						 FROM sales
						 WHERE strftime('%Y-%m', date) = ?
						 GROUP BY product`, year+"-"+month)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var reports []SalesReport
	for rows.Next() {
		var report SalesReport
		err = rows.Scan(&report.Product, &report.Quantity, &report.Total)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		reports = append(reports, report)
	}

	c.JSON(http.StatusOK, reports)
}

func deleteProduct(c *gin.Context) {
	productName := c.Param("product_name")

	db, err := sql.Open("sqlite3", "./sales.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer db.Close()

	stmt, err := db.Prepare("DELETE FROM sales WHERE product=?")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(productName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Product deleted successfully"})
}

func main() {
	router := gin.Default()

	// Настройка маршрута для предоставления статических файлов из директории docs
	router.Static("/docs", "./docs")

	// URL к файлу Swagger в формате JSON
	url := ginSwagger.URL("http://localhost:8080/docs/swagger.json")

	// Настройка Swagger UI
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, url))

	v1 := router.Group("/v1")
	{
		v1.GET("/google/auth", googleAuth)
		v1.GET("/google/callback", googleCallback)
		v1.POST("/register", registerUser)
		v1.POST("/login", loginUser)
		v1.GET("/sales/:year/:month", getSalesReport)
		v1.GET("/products/:product_name/dates", getProductDates)
		v1.POST("/sales", addSalesRecord)
		v1.DELETE("/products/:product_name", deleteProduct)
	}

	router.Run(":8080")
}
