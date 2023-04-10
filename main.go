package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/sessions"

	_ "github.com/mattn/go-sqlite3"
)

type Comment struct {
	ID       int64
	RecordID string
	Author   string
	Body     string
}

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
	Rating         float64
	RatingCount    float64
	RatingTotal    float64
	Email          string
	Comments       []Comment
}

type User struct {
	ID       int
	Email    string
	Password string
	Role     string
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
	err = db.QueryRow("SELECT u.id, u.email, u.password, u.role FROM users u INNER JOIN sessions s ON u.id = s.user_id WHERE s.session_id = ?", sessionId).Scan(&user.ID, &user.Email, &user.Password, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		} else {
			return nil, err
		}
	}

	return &user, nil
}

func searchRecords(query string, price_filter string, rating_filter string, genre_filter []string, special_filter []string) ([]Record, error) {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// PurchasedCount int
	// Rating         float64
	// RatingCount    float64
	// RatingTotal    float64

	sqlQuery := "SELECT id, title, artist, genre, price, image_path, PurchasedCount, Rating FROM records WHERE (title LIKE ? OR artist LIKE ?)"
	var args []interface{}
	args = append(args, "%"+query+"%", "%"+query+"%", "%"+query+"%")

	if len(genre_filter) > 0 {
		genres := strings.Join(genre_filter, "', '")
		sqlQuery += fmt.Sprintf(" AND genre IN ('%s')", genres)
	}

	if len(special_filter) > 0 {
		for i := 0; i < len(special_filter); i++ {
			if special_filter[i] == "bestseller" {
				sqlQuery += " AND PurchasedCount > 51"
			} else {
				sqlQuery += " AND " + special_filter[i] + " = 1"
			}
		}
	}

	if price_filter != "" {
		switch price_filter {
		case "asc":
			sqlQuery += " ORDER BY price ASC"
		case "desc":
			sqlQuery += " ORDER BY price DESC"
		case "0-10":
			sqlQuery += " AND price >= 0 AND price <= 10"
		case "10-20":
			sqlQuery += " AND price >= 10 AND price <= 20"
		case "20-30":
			sqlQuery += " AND price >= 20 AND price <= 30"
		}
	}

	if rating_filter != "" {
		switch rating_filter {
		case "asc":
			sqlQuery += " ORDER BY rating ASC"
		case "desc":
			sqlQuery += " ORDER BY rating DESC"
		case "1":
			sqlQuery += " AND rating >= 0 AND rating < 1.49"
		case "2":
			sqlQuery += " AND rating >= 1.5 AND rating < 2.49"
		case "3":
			sqlQuery += " AND rating >= 2.5 AND rating < 3.49"
		case "4":
			sqlQuery += " AND rating >= 3.5 AND rating < 4.49"
		case "5":
			sqlQuery += " AND rating >= 4.5"
		}
	}

	println(sqlQuery)

	rows, err := db.Query(sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		var record Record
		if err := rows.Scan(&record.ID, &record.Title, &record.Artist, &record.Genre, &record.Price, &record.ImagePath, &record.PurchasedCount, &record.Rating); err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		query := r.FormValue("q")

		records, err := searchRecords(query, "", "", nil, nil)
		if err != nil {
			http.Error(w, "1Internal Server Error", http.StatusInternalServerError)
			return
		}

		t, err := template.ParseFiles("templates/allrecords.tmpl")
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
	http.Redirect(w, r, "/wishlist", http.StatusFound)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	stmt, err := db.Prepare("INSERT INTO users (email, password) VALUES (?, ?)")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(email, password)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func getRecordById(id string) (*Record, error) {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var record Record
	err = db.QueryRow("SELECT id, title, artist, genre, price, image_path, new_item, PurchasedCount, Sale, PreOrder, rating, rating_count, rating_total FROM records WHERE id = ?", id).Scan(&record.ID, &record.Title, &record.Artist, &record.Genre, &record.Price, &record.ImagePath, &record.NewItem, &record.PurchasedCount, &record.Sale, &record.PreOrder, &record.Rating, &record.RatingCount, &record.RatingTotal)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

func viewRecord(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	id := r.FormValue("id")
	if id == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	record, err := getRecordById(id)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	record.Email = "false"
	//record.Rating = record.RatingTotal / record.RatingCount

	sessionCookie, err := r.Cookie("session_id")
	if err == nil {
		session := &Session{ID: sessionCookie.Value}
		user, err := getUserBySessionId(session.ID)
		if err == nil {
			if user != nil {
				record.Email = user.Role
			}
		}
	}
	comments, _ := getCommentsByRecordID(id)

	record.Comments = comments

	tmpl, err := template.ParseFiles("templates/record.tmpl")
	if err != nil {
		http.Error(w, "Internal Server Errorzz", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, record)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func addRating(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id := r.FormValue("id")
	ratingStr := r.FormValue("rating")

	rating, err := strconv.Atoi(ratingStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	db.QueryRow("UPDATE records SET rating_total = rating_total + ?, rating_count = rating_count + 1 WHERE id = ?", rating, id).Scan()
	db.Exec("UPDATE records SET rating = CASE WHEN rating_count > 0 THEN rating_total / rating_count ELSE 0 END WHERE id = ?", id)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func viewWishlist(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	session := &Session{ID: sessionCookie.Value}
	user, err := getUserBySessionId(session.ID)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT r.id, r.title, r.artist, r.price FROM wishlist w JOIN records r ON w.record_id=r.id WHERE w.user_id=?", user.ID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var records []Record
	for rows.Next() {
		var record Record
		err = rows.Scan(&record.ID, &record.Title, &record.Artist, &record.Price)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		records = append(records, record)
	}
	err = rows.Err()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	tmpl, err := template.ParseFiles("templates/wishlist.tmpl")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, records)

}

func allRecords(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	sort := r.URL.Query().Get("sort")

	records, err := queryRecords(db, sort)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		query := r.FormValue("q")
		price_filter := r.FormValue("price-filter")
		rating_filter := r.FormValue("rating-filter")
		genre_filter := r.Form["genre-filter[]"]
		special_filter := r.Form["special-filter[]"]
		genres := strings.Join(genre_filter, "', '")
		println(genres)

		records, err = searchRecords(query, price_filter, rating_filter, genre_filter, special_filter)
		if err != nil {
			http.Error(w, "1Internal Server Error", http.StatusInternalServerError)
			return
		}

	}

	data := struct {
		Records  []Record
		User     *User
		OneThird int
		TwoThird int
		Genres   []string
	}{
		Records:  records,
		User:     nil,
		OneThird: 1,
		TwoThird: 1,
		Genres:   getDistinctGenres(),
	}
	if len(records) > 1 {
		data.OneThird = len(records) / 3
		data.TwoThird = (len(records) / 3) * 2
	}

	user := User{
		ID:       100,
		Email:    "false",
		Password: "password",
		Role:     "false",
	}
	data.User = &user

	sessionCookie, err := r.Cookie("session_id")
	if err == nil {
		session := &Session{ID: sessionCookie.Value}
		user, err := getUserBySessionId(session.ID)
		if err == nil {
			if user != nil {
				data.User = user
			}
		}
	}

	s := "templates/index.tmpl"
	if strings.Contains(r.URL.Path, "allRecords") {
		s = "templates/allrecords.tmpl"
	}

	tmpl, err := template.ParseFiles(s)

	if err != nil {
		http.Error(w, "Internal Server Errorssssssss", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func getDistinctGenres() []string {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return nil
	}
	defer db.Close()
	rows, err := db.Query("SELECT DISTINCT genre FROM records")
	if err != nil {
		print(err)
	}
	defer rows.Close()

	genres := []string{}
	for rows.Next() {
		var genre string
		err := rows.Scan(&genre)
		if err != nil {
			print(err)
		}
		genres = append(genres, genre)
	}

	return genres
}

func addRecord(record Record) error {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return err
	}
	defer db.Close()

	stmt, err := db.Prepare("INSERT INTO records(title, artist, genre, price, rating, image_path, rating_count) VALUES (?, ?, ?, ?, ?, ?, 0)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(record.Title, record.Artist, record.Genre, record.Price, record.Rating, record.ImagePath)
	if err != nil {
		return err
	}

	return nil
}

func addRecordHandler(w http.ResponseWriter, r *http.Request) {

	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	session := &Session{ID: sessionCookie.Value}
	user, err := getUserBySessionId(session.ID)
	if err != nil || user == nil || user.Role != "admin" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if r.Method == "POST" {

		err := r.ParseMultipartForm(32 << 20) // 32 MB
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		title := r.FormValue("title")
		artist := r.FormValue("artist")
		genre := r.FormValue("genre")
		price, err := strconv.ParseFloat(r.FormValue("price"), 64)
		if err != nil {
			http.Error(w, "Invalid price", http.StatusBadRequest)
			return
		}
		image, handler, err := r.FormFile("image")
		if err != nil {
			http.Error(w, "Error uploading image", http.StatusBadRequest)
			return
		}
		defer image.Close()
		fileName := ""

		sessionCookie, err := r.Cookie("session_id")
		if err == nil {
			session := &Session{ID: sessionCookie.Value}
			user, err := getUserBySessionId(session.ID)
			if err == nil {
				if user != nil {
					timestamp := time.Now().Format("20060102150405")
					fileName = strconv.Itoa(user.ID) + "_" + timestamp + "_" + handler.Filename
				}
			}
		}

		out, err := os.Create("./public/img/" + fileName)
		if err != nil {
			http.Error(w, "Error saving image file", http.StatusInternalServerError)
			return
		}
		defer out.Close()
		_, err = io.Copy(out, image)
		if err != nil {
			http.Error(w, "Error saving image file", http.StatusInternalServerError)
			return
		}

		record := Record{Title: title, Artist: artist, Genre: genre, Price: price, ImagePath: fileName, PurchasedCount: 0, Rating: 0}
		if err := addRecord(record); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		tmpl, err := template.ParseFiles("templates/addrecord.tmpl")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, ""); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func editRecordHandler(w http.ResponseWriter, r *http.Request) {

	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	session := &Session{ID: sessionCookie.Value}
	user, err := getUserBySessionId(session.ID)
	if err != nil || user == nil || user.Role != "admin" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if r.FormValue("editID") != "" {
		tmpl, err := template.ParseFiles("templates/editrecord.tmpl")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		editID := r.FormValue("editID")

		record, err := getRecordByID(editID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, record); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if r.Method == "POST" {

		recordID := r.FormValue("id")

		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		title := r.FormValue("title")
		artist := r.FormValue("artist")
		genre := r.FormValue("genre")
		priceStr := strings.Replace(r.FormValue("price"), ",", ".", -1)
		price, err := strconv.ParseFloat(priceStr, 64)
		if err != nil {
			http.Error(w, "Invalid price", http.StatusBadRequest)
			return
		}

		db, err := sql.Open("sqlite3", "records.db")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer db.Close()

		stmt, err := db.Prepare("UPDATE records SET title=?, artist=?, genre=?, price=? WHERE id=?")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer stmt.Close()
		_, err = stmt.Exec(title, artist, genre, price, recordID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func getRecordByID(id string) (Record, error) {
	var record Record

	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return record, err
	}
	defer db.Close()

	err = db.QueryRow("SELECT id, title, artist, genre, price, image_path FROM records WHERE id = ?", id).Scan(&record.ID, &record.Title, &record.Artist, &record.Genre, &record.Price, &record.ImagePath)
	if err != nil {
		return record, err
	}

	return record, nil
}
func accountHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		User *User
	}{
		User: nil,
	}
	user := User{
		ID:       100,
		Email:    "false",
		Password: "password",
		Role:     "false",
	}
	data.User = &user

	sessionCookie, err := r.Cookie("session_id")
	if err == nil {
		session := &Session{ID: sessionCookie.Value}
		user, err := getUserBySessionId(session.ID)
		if err == nil {
			if user != nil {
				data.User = user
			}
		}
	}
	tmpl, err := template.ParseFiles("templates/login.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
func addCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		recordID := r.FormValue("record_id")
		author := r.FormValue("author")
		body := r.FormValue("body")

		db, err := sql.Open("sqlite3", "records.db")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer db.Close()

		stmt, err := db.Prepare("INSERT INTO comments(record_id, author, comment) VALUES (?, ?, ?)")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		_, err = stmt.Exec(recordID, author, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getCommentsByRecordID(recordID string) ([]Comment, error) {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, record_id, author, comment FROM comments WHERE record_id = ?", recordID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	comments := []Comment{}
	for rows.Next() {
		var comment Comment
		err := rows.Scan(&comment.ID, &comment.RecordID, &comment.Author, &comment.Body)
		if err != nil {
			return nil, err
		}
		comments = append(comments, comment)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return comments, nil
}

func addToCartHandler(w http.ResponseWriter, r *http.Request) {
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
	println(recordID)
	if recordID == "" {
		return
	}

	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO cart (user_id, record_id) VALUES (?, ?)", user.ID, recordID)
	if err != nil {
		return
	}
	http.Redirect(w, r, "/cart", http.StatusFound)
}

func cartHandler(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	session := &Session{ID: sessionCookie.Value}
	user, err := getUserBySessionId(session.ID)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT r.id, r.title, r.artist, r.price, r.image_path FROM cart w JOIN records r ON w.record_id=r.id WHERE w.user_id=?", user.ID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var records []Record
	for rows.Next() {
		var record Record
		err = rows.Scan(&record.ID, &record.Title, &record.Artist, &record.Price, &record.ImagePath)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		records = append(records, record)
	}
	err = rows.Err()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	tmpl, err := template.ParseFiles("templates/cart.tmpl")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, records)
}

func orderHandler(w http.ResponseWriter, r *http.Request) {
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

	if r.Method == http.MethodPost {
		r.ParseForm()
		record_id := r.Form["record-id[]"]
		record_count := r.Form["record-count[]"]
		fullname := r.FormValue("fullname")
		// number := r.FormValue("number")
		email := r.FormValue("email")
		address := r.FormValue("address")
		coupon := r.FormValue("coupon")
		total_price := r.FormValue("total-price")

		db, err := sql.Open("sqlite3", "records.db")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer db.Close()
		result, err := db.Exec("INSERT INTO orders (user_id, customer_name, customer_email, delivery_address, total_price, coupon_code) VALUES (?, ?, ?, ?, ?, ?)", user.ID, fullname, email, address, total_price, coupon)
		if err != nil {
			return
		}

		orderID, err := result.LastInsertId()
		if err != nil {
			return
		}

		for i := 0; i < len(record_id); i++ {
			_, err = db.Exec("INSERT INTO order_items (order_id, record_id, quantity) VALUES (?, ?, ?)", orderID, record_id[i], record_count[i])
			if err != nil {
				return
			}
		}

	}
}

func addChatMessageHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

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

	userID := user.ID
	messageText := r.FormValue("message_text")

	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO chat_messages (user_id, message_text) VALUES (?, ?)", userID, messageText)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Chat message added successfully"))
}

// func getChatMessages(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println("getChatMessages called")
// 	data := 1
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(data)
// }

type ChatMessage struct {
	ID       int    `json:"id"`
	UserID   int    `json:"user_id"`
	Text     string `json:"text"`
	Time     string `json:"time"`
	UserName string `json:"user_name"`
}

func getChatMessages(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT chat_messages.id, chat_messages.user_id, chat_messages.message_text, chat_messages.message_time, users.email
		FROM chat_messages
		JOIN users ON chat_messages.user_id = users.id
		ORDER BY chat_messages.message_time DESC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	messages := []ChatMessage{}
	for rows.Next() {
		var id, user_id int
		var text, time, user_name string
		if err := rows.Scan(&id, &user_id, &text, &time, &user_name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		messages = append(messages, ChatMessage{
			ID:       id,
			UserID:   user_id,
			Text:     text,
			Time:     time,
			UserName: user_name,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func chatHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT user_id, message_text, message_time FROM chat_messages ORDER BY message_time ASC")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []ChatMessage
	for rows.Next() {
		var message ChatMessage
		err := rows.Scan(&message.UserID, &message.Text, &message.Time)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/chat.tmpl")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, struct {
		Messages []ChatMessage
	}{
		messages,
	})
}

func main() {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	// db.Exec("DELETE FROM sessions")
	// db.Exec("DELETE FROM chat_messages")

	// db.Exec("DELETE FROM orders")
	// db.Exec("DELETE FROM order_items")

	// for i := 0; i < 100; i++ {
	// 	path := fmt.Sprintf("/record/%d", i)
	// 	http.HandleFunc(path, viewRecord)
	// }
	http.HandleFunc("/addToCart", addToCartHandler)
	http.HandleFunc("/chat", chatHandler)
	http.HandleFunc("/order", orderHandler)
	http.HandleFunc("/cart", cartHandler)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/account", accountHandler)
	http.HandleFunc("/addToWishlist", addToWishlist)
	http.HandleFunc("/wishlist", viewWishlist)
	http.HandleFunc("/allRecords", allRecords)
	http.HandleFunc("/addRecord", addRecordHandler)
	http.HandleFunc("/editRecord", editRecordHandler)
	http.HandleFunc("/addComment", addCommentHandler)
	http.HandleFunc("/addChatMessage", addChatMessageHandler)
	http.HandleFunc("/getChatMessages", getChatMessages)

	http.HandleFunc("/", allRecords)

	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("public/css"))))
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("public/img"))))
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("public/js"))))

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/record", viewRecord)
	http.HandleFunc("/record/add-rating", addRating)

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
		err := rows.Scan(&r.ID, &r.Title, &r.Artist, &r.Genre, &r.Price, &r.ImagePath, &r.NewItem, &r.PurchasedCount, &r.Sale, &r.PreOrder, &r.Rating, &r.RatingCount, &r.RatingTotal)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}
