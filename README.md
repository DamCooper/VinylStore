VinylStore
Project Overview
This project is a web application for a vinyl record store that allows users to browse, search, and purchase vinyl records. Users can also register and login to the website to access additional features such as adding records to a wishlist, commenting on records, and rating records.

REPORT 10
Myrzabekov Farkhat: added functionality to return purchased vinyl to customers.
Nashkenova Ingkar: added newsletter functionality.
We use newsletter subscriptions to build and maintain direct relationships with customers.

REPORT 9
Myrzabekov Farkhat: added handler and template to display the order history of a logged-in user. This function checks if the user is authenticated, retrieves their order history and order items from the database, formats the data and displays it in an HTML page, and sends error responses if any issues occur.

Nashkenova Ingkar: added functionality to listen sample music in our website. The implementation for adding a record's sample audio involves adding a new column "sample_path" to the "records" table in the database to store the file path to the audio sample. Additionally, the "viewRecord" handler is modified to include the audio information when passing data to the template, and the template is also updated to display the audio in the HTML page.

REPORT 8
Myrzabekov Farkhat: added order&purchase system to store all info about sold records.  
Nashkenova Ingkar: added a live chat feature or a ticketing system for users to ask questions

REPORT 7
Myrzabekov Farkhat: redisgn of item filter system.
Nashkenova Ingkar: full redisign of all item display and record info page. 
Myrzabekov Farkhat and Nashkenova Ingkar: both worked on creating design for home page.
Huge design update from old to new and better look website.
finding fonts/colors/images etc.


![2](https://user-images.githubusercontent.com/91084290/230431903-70d88a91-27ea-4ad9-b4cb-214c5e47a21c.png)
![1](https://user-images.githubusercontent.com/91084290/230431874-9875a117-5c3a-4063-b38f-b18f073549b6.png)
![3](https://user-images.githubusercontent.com/91084290/230432523-1c5568ea-14ca-4728-8b7f-1522073c0749.png)






REPORT 6
Myrzabekov Farkhat:
Added item commenting system that handles a POST request sent from a form to add a new comment to a record in the database.
Also added comment display function for each item.
![image](https://user-images.githubusercontent.com/91084290/227905068-cce69342-f196-48aa-a93e-ae20b2a47c95.png)

Nashkenova Ingkar:
Added function to handle requests to edit records.
Added roles system.
Now users with no admin role and guests(not authorized users) can't add new items and change it's values.

![image](https://user-images.githubusercontent.com/91084290/227904880-266aee2f-f1f8-4d9d-bdf2-841995124cce.png)
![image](https://user-images.githubusercontent.com/91084290/227904988-d80071dc-4ab2-4dec-854e-4146bf92a2d8.png)



REPORT 5

![image](https://user-images.githubusercontent.com/91084290/224551630-227ed2d0-2ea4-47cf-b561-309d528b8b4b.png)
![image](https://user-images.githubusercontent.com/91084290/224551651-451c63ac-b127-4618-bd8e-575a628a89e1.png)
![image](https://user-images.githubusercontent.com/91084290/224551670-b8740a26-f074-4f3f-883b-72e0a2625774.png)
![image](https://user-images.githubusercontent.com/91084290/224551688-6c67ec38-9251-4916-83a9-b26ca5220bb1.png)


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
users can click on records to get full info page and give rating

PS. USER SHOULD BE LOGGED IN TO ADD NEW RECORD ===

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

