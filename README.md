# Access Control Policy Service
- Go Web Server, to create access policies and ask for permissions of a subject 

## Endpoints
- /policies -  manage access policies
```shell
curl -i -X POST --url http://localhost:8080/policies
[
    {
        	"Subject": "admin",
        	"Action": "POST",
        	"Resource": "/iot-repository",
        	"ID": "admin",
        	"Effect": "allow"
    }
]
```
```shell
curl -i -X PUT --url http://localhost:8080/policies
[
    {
        	"Subject": "admin",
        	"Action": "has_access_permission",
        	"Resource": "deviceid"
        	"ID": "admin",
        	"Context": {
        		"type": "device",
        		"owner": "user"
        	}
        	"Effect": "allow"
    }
]
```
```shell
curl -i -X GET --url http://localhost:8080/policies?subject=admin
```
```shell
curl -i -X DELETE --url http://localhost:8080/policies?ids=id1,id2
```

- /check - ask for permission (used with kong middleman plugin)
```shell
curl -i -X POST --url http://localhost:8080/access
{
    "headers": {
        "target_method": "GET",
        "target_uri": "/process/schedulerlump",
        "authorization": "Bearer <token>"
    }
}
```

# Requiremnets
## for project
## for Docker image
```
docker pull golang
```

# Types of authorization
- Subjects: 
1. User 
2. Role 

- Actions:
1. HTTP Method
2. Access

- Ressources:
1. URI
2. Device Instance ID
3. Device Type ID

## Examples
1. role admin is allowed to GET on ressource /iot-device-repo
2. user max is allowed to access device instance iot#22323232332 where owner is thomas 
- subset generieren bei web ui: checken eigene devices dann instanzen die freigegeben wurde
- device instanz verwenden beim process exceuter: 
entweder im iot-repo nachfragen und ladon 

# Access Policies
- one policy per subject e.g. role admin and ressource e.g /iot-repository
- one or multiple actions which can be removed or added later 
- policy id is tuple of subject and ressource 
- if permissions of a subject in relation to a ressource should be changed, then the existing policy should be changed and no extra policy be created

# Naming Convention
- Best practices: https://ory.gitbooks.io/hydra/content/access-control.html#best-practices

# Build 
with Docker
```shell
docker build -t ladon .
```

# Run
with docker-compose (with database and port 8080)
```shell
docker-compose up 
```
