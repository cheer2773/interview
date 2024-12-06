
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var jwtKey = []byte("secret_key")

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Task struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Status    string    `json:"status"`
	Content   string    `json:"content"`
	Result    string    `json:"result,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

var (
	users       = map[string]User{}
	tasks       = map[string]Task{}
	tasksMutex  = &sync.Mutex{}
	rateLimiter = map[string]int{}
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s %s - %dms", start.Format(time.RFC3339), r.Method, r.URL.Path, time.Since(start).Milliseconds())
	})
}

func rateLimitingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userIP := strings.Split(r.RemoteAddr, ":")[0]
		if count, exists := rateLimiter[userIP]; exists && count >= 10 {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		rateLimiter[userIP]++
		go func() {
			time.Sleep(1 * time.Minute)
			rateLimiter[userIP]--
		}()
		next.ServeHTTP(w, r)
	})
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	user.ID = fmt.Sprintf("user-%d", time.Now().UnixNano())
	users[user.Username] = user
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	storedUser, exists := users[user.Username]
	if !exists || storedUser.Password != user.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		UserID: storedUser.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func createTask(w http.ResponseWriter, r *http.Request) {
	userID, err := authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var task Task
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	task.ID = fmt.Sprintf("task-%d", time.Now().UnixNano())
	task.UserID = userID
	task.Status = "Created"
	task.CreatedAt = time.Now()

	tasksMutex.Lock()
	tasks[task.ID] = task
	tasksMutex.Unlock()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(task)
}

func translateTask(w http.ResponseWriter, r *http.Request) {
	userID, err := authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	taskID := strings.TrimPrefix(r.URL.Path, "/tasks/")
	tasksMutex.Lock()
	task, exists := tasks[taskID]
	tasksMutex.Unlock()
	if !exists || task.UserID != userID {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	// Simulate LLM API Call
	task.Status = "Translating"
	task.Result = fmt.Sprintf("Translated content of '%s'", task.Content)
	task.Status = "Completed"

	tasksMutex.Lock()
	tasks[task.ID] = task
	tasksMutex.Unlock()

	json.NewEncoder(w).Encode(task)
}

func getTaskStatus(w http.ResponseWriter, r *http.Request) {
	userID, err := authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	taskID := strings.TrimPrefix(r.URL.Path, "/tasks/")
	tasksMutex.Lock()
	task, exists := tasks[taskID]
	tasksMutex.Unlock()
	if !exists || task.UserID != userID {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(task)
}

func downloadTranslatedContent(w http.ResponseWriter, r *http.Request) {
	userID, err := authenticateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	taskID := strings.TrimPrefix(r.URL.Path, "/tasks/")
	tasksMutex.Lock()
	task, exists := tasks[taskID]
	tasksMutex.Unlock()
	if !exists || task.UserID != userID {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	if task.Status != "Completed" {
		http.Error(w, "Translation not completed", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename="translated.json"")
	json.NewEncoder(w).Encode(map[string]string{"content": task.Result})
}

func authenticateRequest(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("Missing token")
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		return "", errors.New("Invalid token")
	}
	return claims.UserID, nil
}

func main() {
	mux := http.NewServeMux()
	mux.Handle("/auth/users", http.HandlerFunc(registerUser))
	mux.Handle("/auth/login", http.HandlerFunc(loginUser))
	mux.Handle("/tasks", http.HandlerFunc(createTask))
	mux.Handle("/tasks/translate", http.HandlerFunc(translateTask))
	mux.Handle("/tasks/status", http.HandlerFunc(getTaskStatus))
	mux.Handle("/tasks/download", http.HandlerFunc(downloadTranslatedContent))

	handler := loggingMiddleware(rateLimitingMiddleware(mux))

	log.Println("Server is running on :8080")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
