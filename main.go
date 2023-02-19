package main

import (
	"database/sql"
	"html/template"
	"net/http"

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

func main() {
	db, err := sql.Open("sqlite3", "records.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	http.HandleFunc("/search", searchHandler)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sort := r.URL.Query().Get("sort")
		records, err := queryRecords(db, sort)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl := template.Must(template.ParseFiles("templates/index.tmpl"))
		err = tmpl.Execute(w, records)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("public/css"))))
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("public/img"))))

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
