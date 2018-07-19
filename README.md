# MarathiDictionaryAPI

## How do I run this project locally?

### 1. Clone the repository:

    git clone https://github.com/vinodnimbalkar/MarathiDictionaryAPI.git
    
### 2. Change Directory:
    cd MarathiDictionaryAPI

### 3. Install dependencies:

    pip install -r requirements.txt

### 4. Run the server:

    python marathiapi.py

### 5. And open 127.0.0.1:5000 in your postman extension.

API Documentation
-----------------

- POST **/user**

    Register a new user.<br>
    The body must contain a JSON object that defines `email` and `password` fields.<br>
    On success a status code 201 is returned. The body of the response contains a JSON object with the newly added user.
    `{'message' : 'New user created!'}`<br>
    On failure status code 400 (bad request) is returned.<br>
    Notes:
    - The password is hashed before it is stored in the database. Once hashed, the original password is discarded.
    - In a production deployment secure HTTP must be used to protect the password in transit.
    
- GET **/login**

    Return an authentication token.<br>
    This request must be authenticated using a HTTP Basic Authentication header.<br>
    On success a JSON object is returned with a field `token` set to the authentication token for the user and a field `duration` set to the (approximate) number of seconds the token is valid. (here only for 30 minute)<br>
    On failure status code 401 (unauthorized) is returned.

- GET **/engmar**

    Return a word with its meaning.<br>
    This request must be authenticated using a HTTP Basic Authentication header. Instead of email and password, the client can provide a valid authentication token in the x-access-token field.<br>
    On success a JSON object with data for the authenticated user is returned.<br>
    On failure status code 401 (unauthorized) is returned.
