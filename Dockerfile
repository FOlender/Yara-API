# Descarga de imagen base de Docker "Ubuntu".
FROM ubuntu:latest

# Actualizo e instalo requerimientos.
RUN apt-get update -y && apt-get upgrade -y && apt-get install python3 python3-pip -y
RUN pip3 install flask flask-restful yara-python memory_profiler

# Copio API.
RUN mkdir /Yara-API/ && mkdir /Yara-API/Rules mkdir /Yara-API/Rules/Compiled && mkdir /Yara-API/Files
COPY --chown=root:root Yara-API.py /Yara-API/Yara-API.py
RUN chmod 755 /Yara-API/Yara-API.py

# Preparo la ejecucion
WORKDIR /Yara-API/
EXPOSE 8080
CMD [ "python3", "./Yara-API.py" ]

