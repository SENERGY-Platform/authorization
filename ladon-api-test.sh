docker build -t ladon .
docker-compose up 
newman run tests_ladon.postman_collection.json 
docker stop ladon 
docker rm ladon 
docker rmi ladon
docker rm ladon-db