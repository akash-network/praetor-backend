from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from logging.config import dictConfig

from .config.config import Config
from .config.log_config import LogConfig
from .exception.praetor_exception import PraetorException
from .utils.scheduler import init_scheduler

dictConfig(LogConfig().dict())

app = FastAPI()


@app.exception_handler(PraetorException)
async def praetor_exception_handler(pe: PraetorException):
    return JSONResponse(
        status_code=pe.status_code,
        content={"status": "error", "error_message": f"{pe.payload}"},
    )

origins = Config.PRAETOR_FRONTEND_URL.split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "OPTIONS", "DELETE"],
    allow_headers=["*"],
)


def create_app():
    """Construct the core application."""
    init_scheduler()

    from .api import system, provider, session, ssh, wallet, dashboard, k8s, persistent_storage, deployment
    app.include_router(system.router)
    app.include_router(provider.router)
    app.include_router(session.router)
    app.include_router(ssh.router)
    app.include_router(wallet.router)
    app.include_router(dashboard.router)
    app.include_router(k8s.router)
    app.include_router(persistent_storage.router)
    app.include_router(deployment.router)

    return app
