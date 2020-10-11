import os, io, yara, fnmatch
from os import listdir
from os.path import isfile, join
from flask import Flask, request, jsonify, json
from werkzeug.utils import secure_filename
from memory_profiler import profile

app = Flask(__name__)

app.config.update(
	# Permite correcta visualizacion de JSON en Body para las respuestas.
	JSONIFY_PRETTYPRINT_REGULAR=True
)

# Add Rule
@app.route('/api/rule', methods=['POST'])
def apirule():
	if not request.is_json: return "Content Type no es JSON", 400
	content = request.get_json() # Rechaza JSON no valido (code 400).
	name = content['name']
	rule = content['rule']
	# Verifico que haya enviado nombre y regla
	if name == '' or not name: return "Nombre de regla no especificado", 400
	# TODO: Verificar con MD5SUM que no exista una regla compilada identica.
	if rule == '' or not rule: return "Regla no especificada", 400
	i = 1
	# Determino ID que tendra la nueva regla.
	while os.path.exists("Rules/%s" % i): i += 1
	with open("Rules/"+str(i), "w") as fo: fo.write(rule)
	# Compilo Regla de Yara
	try:
		YaraRules = yara.compile('Rules/'+str(i))
	except:
		os.remove('Rules/'+str(i))
		return "Regla de YARA mal formada", 400
	# Guardo Regla de Yara compilada en un archivo
	YaraRules.save('Rules/Compiled/'+str(i)+'-Compiled')
	# TODO: Verificar si podria re-cargar todas las reglas compiladas en un archivo junto a esta y luego hacer match selectivo en los otros endpoints.
	content["id"] = i
	return jsonify(content), 201

# Analyze Text
@app.route('/api/analyze/text', methods=['POST'])
def apianalyzetext():
	if not request.is_json: return "Content Type no es JSON", 400
	content = request.get_json() # Rechaza JSON no valido (code 400).
	text = content['text']
	rules = content['rules']
	# Verifico que haya enviado texto y reglas
	if text == '' or not text: return "Texto no especificado", 400
	if rules == '' or not rules: return "Reglas nos especificadas", 400
	i = 1
	# Genero un archivo con el texto, asignandole nombre incremental
	while os.path.exists("Files/%s" % i): i += 1
	with open("Files/"+str(i), "x") as fo: fo.write(text)
	# Matcheo el texto en en archivo con las reglas compiladas especificadas en el Request.
	Resultados = [] # Armo Lista
	for x in rules:
		YaraRules = yara.load('Rules/Compiled/'+str(x['rule_id'])+'-Compiled')
		Matches = YaraRules.match("Files/"+str(i))
		# Armo diccionario
		Diccionario = {'rule_id':str(x['rule_id']),'matched':bool(Matches)}		
		# Lista de diccionarios
		Resultados.append(Diccionario.copy())
	# Elimino el archivo generado con el texto
	os.remove("Files/"+str(i))
	# Armo Body
	Body = {'status': 'ok', 'results': Resultados}
	return jsonify(Body)

# Analyze File
@app.route('/api/analyze/file', methods=['POST'])
def apianalyzefile():
	# Verifico que haya enviado archivo y reglas
	if 'file' not in request.files: return "Archivo no especificado", 400
	if 'rules' not in request.form: return "Reglas no especificadas", 400
	file = request.files['file']
	rules = request.form['rules']
	if file.filename == '' or not file.filename: return "Archivo no especificado", 400
	if rules == '' or not rules: return "Reglas no especificadas", 400
	# Armo lista de reglas.
	rules = list(rules.split(","))
	# Verificaciones de seguridad del nombre del archivo y subida a directorio 
	if file:
		filename = secure_filename(file.filename)
		file.save(os.path.join('Files/', filename))
	# Matcheo el archivo con las reglas compiladas especificadas en el Request.
	Resultados = [] # Armo Lista
	for x in rules:
		YaraRules = yara.load('Rules/Compiled/'+x+'-Compiled')
		Matches = YaraRules.match("Files/"+filename)
		# Armo diccionario
		Diccionario = {'rule_id':x,'matched':bool(Matches)}	
		# Lista de diccionarios
		Resultados.append(Diccionario.copy())
	# Elimino el archivo generado
	os.remove("Files/"+filename)
	# Armo Body
	Body = {'status': 'ok', 'results': Resultados}
	return jsonify(Body)

if __name__ == '__main__':
	# Intento de cargar todas las reglas de Yara compiladas en memoria de a una:
	#for f in listdir("Rules/Compiled/"):
	#	if isfile(join("Rules/Compiled/", f)):
	#		YaraRule = yara.load('Rules/Compiled/'+f)
	#		#print (str(f)+"	"+str(YaraRule))
	app.run(host = '0.0.0.0', port=int("8080"), debug=True) 
	# Debug se mantiene en True para que el error sea detallado al consumir la API.

