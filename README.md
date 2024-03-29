# Yara-API

[Yara](http://virustotal.github.io/yara/) API written in Python to solve "Basic Implementation" of the [ML Challenge](https://github.com/irt-mercadolibre/challenge_yara_FOlender).

## Installation

1.  Install [Git](https://git-scm.com/downloads)
2.  Install [Docker](https://www.docker.io/).
3.  Pull from Github Repo:
```
mkdir Yara-API && cd Yara-API/ && git init && git pull https://github.com/FOlender/Yara-API.git
```
4.  Run Dockerfile:
```
sudo docker build . -t yara-api:v1
```
5. Execute container:
``` 
sudo docker run --rm -d --name Yara-APIv1 -p 8080:8080 yara-api:v1 bash -c "python3 /Yara-API/Yara-API.py"
```

## Maintenance

If the container was runned with the "-rm" argument as indicated in step 5 of the installation process, the container will be remove when stoped, so it is highly recommended to generate new images from the running container once in a while to backup the new rules added to it:
```
# sudo docker commit Yara-API yara-api:v2
```

## DIY

#### Get the code from GitHub and Modify it...

1.  Create local directory and initiate git
```
mkdir Yara-API && cd Yara-API/ && git init
```
2.  Pull Repo from Github:
```
git pull https://github.com/FOlender/Yara-API.git
```
3. Do whatever you want with the code.
4.  Commit changes and Push to Github:
```
git add .
git commit -m 'Message'
git remote add origin https://github.com/FOlender/Yara-API.git
git branch -m master main
git push -u origin main
```

#### Get into the running container to see under the hood...


```
sudo docker exec -i -t Yara-APIv1 /bin/bash
```

## TODO

- [] Replace base image ubuntu:stable with alpine:stable

## Issues

Bugs? Missing features? Errors in the documentation? [Let me know](https://github.com/FOlender/Yara-API/issues/new).

## Notas para ML:

- "Es importante que como esta API va a tener bastante trafico, no tenga que cargar las reglas cada vez que tenga que hacer un análisis."
> Al momento de crear una regla de YARA la misma se almacena en un archivo crudo separado y se compila en un archivo especifico por regla, a fin de poder cumplir la necesidad de matchear texto/archivos contra reglas especificas. Esto genera que cada regla compilada deba cargarse por separado al momento de cada comparacion. La alternativa que consideraba seria recompilarlas todas en un mismo archivo, pero luego en los matcheos no tendria la flexibilidad de seleccionar contra que regla matchear cada texto/archivo.

- **Analyze text POST**: Correccion de comillas (“ y ” por ") en CURL de ejemplo brindado en su Repo:
```
curl --request POST \
  --url http://localhost:8080/api/analyze/text \
  --header 'content-type: application/json' \
  --data '{
	"text": "estoesuntextoaanalizar",
	"rules": [
		{
			"rule_id": 1
		},
		{
			"rule_id": 2
		}
	]
}'
```
