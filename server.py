from flask import Flask, render_template, request 
import os
from werkzeug.utils import secure_filename

from werkzeug.datastructures import ImmutableMultiDict

app = Flask(__name__, static_url_path='/static')
app.config['UPLOAD_FOLDER'] = '../pcap'

@app.route('/')
def index():
  return render_template('index.html')

@app.route('/process', methods = ['POST', 'GET'])
def process():
  # data = request.form
  # print(data)

  file = request.form['file']
  # print(file[0])
  filename = secure_filename(file.filename)
  print(filename)
  # file.save(os.path.join(app.config['UPLOAD_FOLDER'], "input"))
  return "OK"

if __name__ == '__main__':
   app.run(debug = True)