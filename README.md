# Url-Shortener-and-Search
This project shortens URLs, displays them in a table along with a note the user can add to each URL and also the number of times the user clicks on the URL. It also has a search feature in which the user can search by the full URL, short URL, or the note he/she adds. There is also an authentication feature, by which the user can only log in to the database if they are registered.

Here is the deployed project: https://zany-blue-horse-cape.cyclic.app/

To run the project locally, clone the files and type in the terminal npm run devStart. Mongodb Atlas, Node JS needs to be installed on your PC. The server will start running on port 5000, which can be acessed by going to http://localhost:5000/register on which you see a website like this:

![image](https://github.com/Lokesh2626/URL-Shortener-and-Search-/assets/95361104/2fdea36a-5c30-4037-a3a5-081f97017f71)

After entering your details, they get stored in the database and you are redirected to:

![image](https://github.com/Lokesh2626/URL-Shortener-and-Search-/assets/95361104/f723001d-3345-4f85-8e23-4c1d5e30d488)

Finally on entering the correct details you get to the website as below, where you can shorten and store URLs on your local MongoDB database (your database will be empty).

![image](https://github.com/Lokesh2626/URL-Shortener-and-Search-/assets/95361104/20a450c9-1adb-47aa-ab8d-2cad5763f7e7)

To search, you can input any part of the full URL, short URL or the note, which then returns all the possible results for the term. E.g. on searching for 'mong', we get

![image](https://github.com/Lokesh2626/URL-Shortener-and-Search-/assets/95361104/7ba3290f-4bc5-4716-9e11-dc0c8c9cda33)

** Following part not needed if code works fine **

If you do not want to download node_modules / code is not working, type in your project terminal npm init, npm i express mongoose ejs, npm i --save-dev nodemon dotenv, npm i shortid, npm i bcrypt, npm i passport passport-local, npm i express-session express-flash,  npm i method-override. Replace the part in "scripts" in package.json created with "devStart": "nodemon server.js" to use nodemon server (refer to package.json in this repository file). (If terminal is showing error make sure your firewall is allowing access).


**Working of the project:**

Every URL schema has four attributes, full URL, short URL, no. of clicks, note. The short URL is generated by the shortId library and the user is redirected to the homepage. The short URL is then displayed on the homepage table. When the user presses the short URL hyperlink, he/she is redirected to the original full URL by the server. The no. of clicks is also increased be one each time he/she presses it. If the user wishes to add a note to the URL, it is also stored with the URL.

For the search part, the query user types in is compared with all parts of the URL data; full URL, short URL and note irrespective of case. The server then checks the database for all matching strings (even if query is incomplete) by the RegExp command. All the matching URL's are then displayed in the table.

For the authentication, the password taken from the user is stored in a hash format. The server checks the login credentials with the data stored in MongoDB user database and redirects accrodingly. JSON web token is also used for authentication.

**Learning Takeaways:**

The frontend and backend files are coded independently of each other. The database file is also different for easy modification. URL shortener is just a database, which stores a short URL for the user. The frontend can be easily created by BootStrap.

**Resources/References:**

https://www.youtube.com/@WebDevSimplified

https://www.mongodb.com/docs/

**Lokesh Kolhe**
