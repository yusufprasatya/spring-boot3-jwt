<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>

<h1>JWT Authentication System with Spring Boot 3</h1>

<h2>Overview</h2>
<p>This project implements a user authentication and authorization system using <strong>JWT (JSON Web Token)</strong> for secure communication. The backend is built using <strong>Spring Boot</strong>, and the application is designed to manage user login, registration, and token-based authentication.</p>

<h2>Key Features</h2>
<ul>
    <li><strong>User Registration:</strong> New users can register by providing a name, email, and password.</li>
    <li><strong>Login:</strong> Users can log in with their credentials to receive a JWT for subsequent requests.</li>
    <li><strong>JWT Token:</strong> A signed JWT is generated after a successful login, which is used to authenticate future requests.</li>
    <li><strong>Secure Endpoints:</strong> Routes are protected using JWT authentication, and only authenticated users can access certain resources.</li>
    <li><strong>Token Validation:</strong> The server validates the token with each request to ensure the user’s authenticity.</li>
    <li><strong>Password Hashing:</strong> Passwords are securely hashed using <strong>BCrypt</strong> before storage in the database.</li>
</ul>

<h2>Project Structure</h2>
<pre>
src
│
├── main
│   ├── java
│   │   └── com.example.jwt
│   │       ├── config       # Security and Application Configuration files
│   │       ├── controller   # REST Controllers for handling user requests
│   │       ├── filter       # Custom JWT filter for request validation
│   │       ├── model        # Entity classes and data models
│   │       ├── repository   # JPA Repositories for database interaction
│   │       ├── service      # Business logic and JWT management services
│   │       └── JwtApplication.java  # Main Application Entry Point
│   └── resources
│       ├── application.properties  # Application configuration
│       └── schema.sql              # SQL scripts for database schema
│
└── test  # Unit and integration tests
</pre>

<h2>Getting Started</h2>

<h3>Prerequisites</h3>
<ul>
    <li><strong>Java 17</strong> or higher</li>
    <li><strong>Maven</strong> for dependency management</li>
    <li><strong>PostgreSQL</strong> for database</li>
</ul>

<h3>Installation</h3>
<ol>
    <li>Clone the repository:
        <pre>
git clone https://github.com/yusufprasatya/spring-boot3-jwt.git
cd spring-boot3-jwt
        </pre>
    </li>

<li>Configure the database:
        <p>In the <code>application.properties</code> file, set up your PostgreSQL connection details:</p>
        <pre>
spring.datasource.url=jdbc:postgresql://localhost:5432/your_database
spring.datasource.username=your_username
spring.datasource.password=your_password
</pre>
</li>

<li>Run the application:
<pre>mvn spring-boot:run</pre>
</li>
</ol>

<h3>Usage</h3>
<ul>
    <li><strong>Register a user:</strong> Send a <code>POST</code> request to <code>/auth/register</code> with the following payload:
        <pre>
{
    "fullName": "John Doe",
    "email": "john.doe@example.com",
    "password": "securePassword123"
}
        </pre>
    </li>

<li>
<strong>Login a user:</strong> Send a <code>POST</code> request to <code>/auth/login</code> with the following payload:
        <pre>{
    "email": "john.doe@example.com",
    "password": "securePassword123"
}</pre>

</li>
<p>You will receive a JWT token upon successful login.</p>

<li><strong>Access protected endpoint:</strong> Add the token to the <code>Authorization</code> header for protected routes:
        <pre>Authorization: Bearer &lt;your_jwt_token&gt;</pre>
</li>
</ul>

<h2>Security</h2>
<p>This project uses <strong>Spring Security</strong> and <strong>JWT</strong> to ensure secure API access. The <code>JwtAuthenticationFilter</code> ensures that every incoming request to protected endpoints has a valid JWT token, and user authentication is managed with the help of <code>AuthenticationManager</code>.</p>

<h2>Endpoints</h2>
<ul>
    <li><code>/auth/register</code> (POST) - Register a new user.</li>
    <li><code>/auth/login</code> (POST) - Authenticate a user and return a JWT.</li>
    <li><code>/user/me</code> (GET) - Get details of the currently authenticated user (JWT required).</li>
</ul>

<h2>JWT Configuration</h2>
<ul>
    <li><strong>Secret Key:</strong> Defined in <code>application.properties</code> as <code>security.jwt.secret-key</code>. This key is used to sign the JWT.</li>
    <li><strong>Expiration Time:</strong> Token expiration time is defined as <code>security.jwt.expiration-time</code> (in milliseconds).</li>
</ul>

<h3>Example <code>.env</code> Configuration</h3>
<pre>
security.jwt.secret-key=your-secret-key
security.jwt.expiration-time=86400000  # 1 day in milliseconds
</pre>

<h2>Tests</h2>
<p>Unit and integration tests are available in the <code>test</code> directory. To run the tests, use:</p>
<pre>mvn test</pre>

<h2>Contributing</h2>
<p>Feel free to fork this repository and make improvements. Pull requests are welcome!</p>

</body>
</html>
