# authorization-module

The Authorization Module is an ASP.NET Core project designed to handle user authorization. It provides functionality for user authentication, access control, and permissions management. This repository contains the source code for the authorization-module and includes a Dockerfile for easy deployment using Docker.

## License

This project is licensed under the [MIT License](LICENSE).

## Prerequisites

To run this project on your local machine, you need to have the following dependencies installed:

- Docker: [Install Docker](https://docs.docker.com/get-docker/)

## Getting Started

Follow these steps to get the Authorization Module project up and running on your local machine using Docker:

1. Clone this repository to your local machine:

   ```shell
   git clone https://github.com/Kamil-Zuki/authorization-module.git
   ```
2. Navigate to the project directory:
   ```shell
   cd authorization-module
   ```
3. Build the Docker image using the provided Dockerfile:
   ```chell
   docker build -t authorization-module .
   ```
5. Run a Docker container using the built image:
   ```chell
   docker run -d -p 8080:80 authorization-module
   ```
   This command will start a Docker container running the Authorization Module project and expose it on http://localhost:8080.
7. Open your web browser and navigate to http://localhost:8080 to access the Authorization Module.

## Usage
Once the Docker container is running, you can use the Authorization Module by following these steps:

1. Open your web browser and go to http://localhost:8080 (or the appropriate address if you changed the port mapping in the docker run command).
2. Use the provided authentication and authorization endpoints to manage user authentication, access control, and permissions. Example:
   ```shell
   POST http://localhost:8080/api/auth/login
   ```
   This endpoint can be used to log in a user and obtain an authentication token for subsequent requests.
3. Explore the Swagger API documentation to learn more about available endpoints and their usage. You can access it at:
   ```shell
   http://localhost:8080/auth/swagger
   ```
The Swagger UI provides an interactive interface to explore and test the API.

## Contributing
Contributions to the Authorization Module project are welcome! If you encounter any issues or have suggestions for improvements, please create a new issue or submit a pull request.




