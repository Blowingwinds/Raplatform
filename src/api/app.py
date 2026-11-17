"""FastAPI application factory for the prototype control plane."""

from fastapi import FastAPI


def create_app() -> FastAPI:
    app = FastAPI(title="Raplatform", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "raplatform"}

    return app


app = create_app()
