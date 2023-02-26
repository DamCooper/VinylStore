package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/gorilla/sessions"

	_ "github.com/mattn/go-sqlite3"
)

type Record struct {
	ID             int
	Title          string
	Artist         string
	Genre          string
	Price          float64
	ImagePath      string
	NewItem        bool
	Sale           bool
	PreOrder       bool
	PurchasedCount int
}

type User struct {
	ID       int
	Email    string
	Password string
}

type Session struct {
	ID    string
	Email string
}

var store = sessions.NewCookieStore([]byte("secret"))

func verifyUser(email, password string) (*User, error) {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	user := &User{}
	row := db.QueryRow("SELECT id, email, password FROM users WHERE email = ?", email)
	err = row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	if user.Password != password {
		return nil, fmt.Errorf("incorrect password")
	}

	return user, nil
}

func createSession(user *User) (*Session, error) {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	sessionIDBytes := make([]byte, 32)
	_, err = rand.Read(sessionIDBytes)
	if err != nil {
		return nil, err
	}
	sessionID := base64.StdEncoding.EncodeToString(sessionIDBytes)

	stmt, err := db.Prepare("INSERT INTO sessions (user_id, session_id) VALUES (?, ?)")
	if err != nil {
		return nil, err
	}
	_, err = stmt.Exec(user.ID, sessionID)
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:    sessionID,
		Email: user.Email,
	}
	return session, nil
}

func deleteSession(session *Session) error {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec("DELETE FROM sessions WHERE session_id = ?", session.ID)
	if err != nil {
		return err
	}

	return nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := r.Form.Get("email")
	password := r.Form.Get("password")
	user, err := verifyUser(email, password)
	print(email)
	print(password)

	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	session, err := createSession(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionCookie := &http.Cookie{
		Name:  "session_id",
		Value: session.ID,
		Path:  "/",
	}
	http.SetCookie(w, sessionCookie)
	http.Redirect(w, r, "/", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	session := &Session{ID: sessionCookie.Value}
	err = deleteSession(session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionCookie.Expires = time.Now().AddDate(0, 0, -1)
	http.SetCookie(w, sessionCookie)
	http.Redirect(w, r, "/", http.StatusFound)
}

func getUserBySessionId(sessionId string) (*User, error) {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var user User
	err = db.QueryRow("SELECT u.id, u.email, u.password FROM users u INNER JOIN sessions s ON u.id = s.user_id WHERE s.session_id = ?", sessionId).Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		} else {
			return nil, err
		}
	}

	return &user, nil
}

func searchRecords(query string) ([]Record, error) {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT title, artist, genre, price, image_path, PurchasedCount FROM records WHERE title LIKE ? OR artist LIKE ? OR genre LIKE ?", "%"+query+"%", "%"+query+"%", "%"+query+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		var record Record
		if err := rows.Scan(&record.Title, &record.Artist, &record.Genre, &record.Price, &record.ImagePath, &record.PurchasedCount); err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		query := r.FormValue("query")

		records, err := searchRecords(query)
		if err != nil {
			http.Error(w, "1Internal Server Error", http.StatusInternalServerError)
			return
		}

		t, err := template.ParseFiles("templates/index.tmpl")
		if err != nil {
			http.Error(w, "2Internal Server Error", http.StatusInternalServerError)
			return
		}

		t.Execute(w, records)
	}
}

func addToWishlist(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	sessionID := cookie.Value

	user, err := getUserBySessionId(sessionID)
	if err != nil || user == nil {
		return
	}

	recordID := r.FormValue("record_id")
	if recordID == "" {
		return
	}

	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO wishlist (user_id, record_id) VALUES (?, ?)", user.ID, recordID)
	if err != nil {
		return
	}
}

func main() {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/wishlist", addToWishlist)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sort := r.URL.Query().Get("sort")
		records, err := queryRecords(db, sort)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := struct {
			Records []Record
			Email   string
		}{
			Records: records,
			Email:   "false",
		}

		sessionCookie, err := r.Cookie("session_id")
		if err == nil {
			session := &Session{ID: sessionCookie.Value}
			user, err := getUserBySessionId(session.ID)
			if err == nil {
				if user != nil {
					print(user.Email)
					data.Email = user.Email
				}
			}
		}

		tmpl, err := template.ParseFiles("templates/index.tmpl")
		if err != nil {
			http.Error(w, "Internal Server Errorssssssss", http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	})

	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("public/css"))))
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("public/img"))))

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}

func queryRecords(db *sql.DB, sort string) ([]Record, error) {
	sortClause := ""
	switch sort {
	case "price":
		sortClause = "ORDER BY Price"
	case "title":
		sortClause = "ORDER BY Title"
	case "artist":
		sortClause = "ORDER BY Artist"
	case "genre":
		sortClause = "ORDER BY Genre"
	}

	rows, err := db.Query("SELECT * FROM records " + sortClause)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		var r Record
		err := rows.Scan(&r.ID, &r.Title, &r.Artist, &r.Genre, &r.Price, &r.ImagePath, &r.NewItem, &r.PurchasedCount, &r.Sale, &r.PreOrder)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}
