import os
import uuid

from flask import Flask, render_template, request, send_file

from . import converter

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/healthz", methods=["GET"])
def healthz():
    return {"status": "ok"}, 200


@app.route("/convert", methods=["POST"])
def convert():
    source = request.form.get("url", "")

    try:
        job_dir, output_path = converter.render_url(source)

        download_name = f"html2pdf-{uuid.uuid4().hex[:8]}.pdf"
        response = send_file(
            output_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=download_name,
        )
        response.call_on_close(lambda: converter.cleanup(job_dir))
        return response

    except converter.ConversionError as exc:
        return render_template("index.html", error=str(exc)), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
