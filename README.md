# VinylStore
REPORT 5
Myrzabekov Farkhat:  
go template to display a user's wishlist using a table and go handler to pass specific logged in users wishlist for template
HTML page for adding a new vinyl record to a database
parsing the form data for the new record's title, artist, genre, and price also gets the image file

Nashkenova Ingkar:
redisign of searching and filtering
two forms on a web page, one for searching and one for filtering records based on price and rating
also go handler to apply filters and search to display data based on queries.
processing the uploaded image for new added record by creating a unique filename, saving the image file to the server

worked together on:
rating system is complete now, users can rate vinyl records and display is working fine.

REPORT 4
Myrzabekov Farkhat: Added registration to users. 
Nashkenova Ingkar: Added rating system to store.

REPORT 3

Myrzabekov Farkhat: Implemented functionality to login and logout for users. Also added sessions table to db to keep logged users in their accounts using "github.com/gorilla/sessions" library. 
You can try logging in to website using "user" as login and as password.

Nashkenova Ingkar: Added a function that adds a record to the wishlist for the currently logged in user. It starts by getting the session ID from the session cookie of the current request and uses the session ID to retrieve the user object for the current session then insert a new wishlist item into the database using the user's ID and the record ID obtained from the request form data. 
For now wishlist can be seen only in database table, not in website UI.


REPORT 2
Myrzabekov Farkhat: I have added 2 new fieilds to the records database such as sale and preorder and worked on website design by adding 3d model iframe;

Nashkenova Ingkar: I added new fields to records table (New Items, BestSellers), worked on site design css and go template.



REPORT 1

Myrzabekov Farkhat: I have worked on database creation and implemented the struct Record to store all main info 
about vinyl recordings like ID, Title, Artist,Genre,Price,ImagePath and worked on rendering(passing) the data to templates.
I have decided to suggest my teammate to use SQLite to store our data, because it is lightweight and easy to develop. 
Also I have helped on debugging the code and installing all the software needed to complete the task.

Nashkenova Ingkar: I have designed project structure especially how to represent vinyls list. I have come up with
idea of adding sorting system and implemented it in code based on different fields such as price, author and etc.
Also I have added functionality to search vinyls by keywords, so if you type Ed Sheeran it will display all the 
vinyls containing Ed Sheeran keyword in title or author. 

