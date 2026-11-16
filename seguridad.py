"""Aplica y verifica la política de seguridad (CSP) de la página.

Correr después de tocar el <style> de 404.html: recalcula su huella y la pone
en 404.html (meta) y en firebase.json (encabezado). Sin argumentos solo verifica.
    python seguridad.py            -> verifica (sale con error si algo no coincide)
    python seguridad.py --aplicar  -> recalcula y escribe
"""
import base64, hashlib, json, re, sys, pathlib

sys.stdout.reconfigure(encoding="utf-8")
WEB = pathlib.Path(__file__).parent
ICONOS = ('<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"'
          ' integrity="sha384-XGjxtQfXaH2tnPFa9x+ruJTuLE3Aa6LhHSWRr1XeTyhezb4abCG4ccI5AkVDxqC+" crossorigin="anonymous">')


def huella_404():
    html = (WEB / "404.html").read_bytes().decode("utf-8")
    estilo = re.search(r"<style>(.*?)</style>", html, re.S).group(1)
    return "sha256-" + base64.b64encode(hashlib.sha256(estilo.encode("utf-8")).digest()).decode()


def csp(extra=""):
    # En <meta> no valen frame-ancestors (va solo en el encabezado de Firebase).
    return ("default-src 'none'; style-src 'self' https://fonts.googleapis.com https://cdn.jsdelivr.net"
            f"{extra}; font-src https://fonts.gstatic.com https://cdn.jsdelivr.net; img-src 'self'; "
            "base-uri 'none'; form-action 'none'; upgrade-insecure-requests")


def meta(extra=""):
    return (f'<meta http-equiv="Content-Security-Policy" content="{csp(extra)}">\n'
            '<meta name="referrer" content="strict-origin-when-cross-origin">\n')


def aplicar():
    h = huella_404()
    for nombre, extra in (("index.html", ""), ("404.html", f" '{h}'")):
        p = WEB / nombre
        t = p.read_bytes().decode("utf-8")
        t = re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>\n<meta name="referrer"[^>]*>\n', "", t)
        t = t.replace('<meta name="viewport" content="width=device-width, initial-scale=1">\n',
                      '<meta name="viewport" content="width=device-width, initial-scale=1">\n' + meta(extra), 1)
        t = re.sub(r'<link rel="stylesheet" href="https://cdn\.jsdelivr\.net/npm/bootstrap-icons@1\.11\.3/font/bootstrap-icons\.min\.css"[^>]*>',
                   ICONOS, t)
        p.write_bytes(t.encode("utf-8"))
    f = WEB / "firebase.json"
    t = f.read_bytes().decode("utf-8")
    t = re.sub(r"'sha256-[^']+'", f"'{h}'", t)
    f.write_bytes(t.encode("utf-8"))
    print("aplicado, huella del 404:", h)


def verificar():
    h = huella_404()
    errores = []
    idx = (WEB / "index.html").read_text(encoding="utf-8")
    e404 = (WEB / "404.html").read_text(encoding="utf-8")
    fb = json.loads((WEB / "firebase.json").read_text(encoding="utf-8"))
    enc = {x["key"]: x["value"] for x in fb["hosting"]["headers"][0]["headers"]}
    if csp() not in idx: errores.append("index.html sin la CSP")
    if csp(f" '{h}'") not in e404: errores.append("404.html: la huella de su <style> no coincide")
    if f"'{h}'" not in enc["Content-Security-Policy"]: errores.append("firebase.json: la huella del 404 no coincide")
    for nombre, t in (("index.html", idx), ("404.html", e404)):
        if "<script" in t: errores.append(f"{nombre} tiene <script> (la CSP lo bloquea)")
        if re.search(r'\sstyle="', t): errores.append(f"{nombre} tiene style= suelto (la CSP lo bloquea)")
        if "bootstrap-icons" in t and ICONOS not in t: errores.append(f"{nombre}: íconos sin verificación (SRI)")
        for a in re.findall(r'<a [^>]*target="_blank"[^>]*>', t):
            if "noopener" not in a: errores.append(f"{nombre}: enlace externo sin noopener")
    for e in errores: print("ERROR:", e)
    print("OK" if not errores else f"{len(errores)} problema(s)")
    return not errores


if __name__ == "__main__":
    if "--aplicar" in sys.argv:
        aplicar()
    sys.exit(0 if verificar() else 1)
