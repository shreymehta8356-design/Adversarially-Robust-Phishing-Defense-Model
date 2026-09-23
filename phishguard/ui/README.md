# Analyst console

The console is shipped **inside the Python package** at
`src/phishguard/static/index.html` so that it is present in the installed wheel
and in the container image, not only in a source checkout.

An earlier revision kept the canonical copy here and resolved it at runtime with
`Path(__file__).parents[3] / "ui"`. That is correct for a source checkout and
wrong for every other layout: in the Docker image it resolved to
`/install/lib/python3.11/ui/index.html`, so the console — the primary interface,
and the first thing the deployment guide tells you to open — returned "asset not
found". The file now travels with the package.

To edit the console, edit `src/phishguard/static/index.html`.
