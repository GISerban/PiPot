from flask import Flask, render_template, jsonify
import glob, json, os
app = Flask(__name__, template_folder='templates')
DATA_DIR = '/data'

@app.route("/")
def index():
    metas = sorted(glob.glob(os.path.join(DATA_DIR, 'meta', '*.json')), key=os.path.getmtime, reverse=True)[:200]
    events = []
    for m in metas:
        try:
            events.append(json.load(open(m)))
        except:
            pass
    return render_template('index.html', events=events)

@app.route("/api/events")
def api_events():
    metas = sorted(glob.glob(os.path.join(DATA_DIR, 'meta', '*.json')), key=os.path.getmtime, reverse=True)[:500]
    events = []
    for m in metas:
        try:
            events.append(json.load(open(m)))
        except:
            pass
    return jsonify(events)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
