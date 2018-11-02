# Occurrences API REST
API REST for treatment and registration of occurrences in a urban environment.

## Getting Started

To run this API is need that have the python file. This api was tested using POSTMAN app.

### Prerequisites

For run this api you need to install the following python libraries on your computer:
. flask 
. flask_sqlalchemy
. psycopg2
. werkzeug
. jwt



### Installing

Run the 'occurrencies_api.py' python file and create your admin user using the endpoint /user POST set username and password attributes. 

Sign in your account with endpoint /login and method GET.

Create a occurrency by using endpoind /occurrencies and method POST and set description, category, latitude, longitude.

Update the state of occurrency using endpoint /occurrencies/<occurrency_id>, method PUT and state attribute. Attribute state must be "validado" or "resolvido"



## Endpoints

/user
Method=POST -> Create a user in DB. Admin is first user created and other users promoted by this. Requested attributes: username, password
/user
Method=GET -> Show all users in database (Login required in a admin account)

/user/<username>
Method=PUT -> Promote a user <username> (Login required in a admin account)

/login 
Method=GET -> Sign in into a user account. (Basic Auth)

/occurrencies 
Method=GET -> Show all occurencies  (Login required)

/occurrencies
Method=POST -> Create a occurrence (Login required) Requested attributes: escription, category, latitude, longitude
       
/occurrencies/author/<username>
Method=GET -> how all occurrencies reported by username (Login required)

/occurrencies/category/<category> 
Method=GET -> Show all occurrencies filtered by category (Login required)

/occurrencies/<occurrence_id>
Method=PUT -> Update the state of an occurrence to "validado" or "resolvido" (Login required) Requests attributes: state
Detais: 
. It's only possible to change to "validado" if user is admin.
. It's only possible to change to "resolvido" if user is the author of occurrence.

## Running the tests

It can be tested using the POSTMAN collection present in POSTMAN folder.


