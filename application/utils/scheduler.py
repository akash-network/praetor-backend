import atexit
from apscheduler.schedulers.background import BackgroundScheduler

from application.config.config import Config
from application.service.provider import refresh_provider_list, remove_providers_session


def _refresh_providers():
    refresh_provider_list()  # For mainnet
    refresh_provider_list(is_testnet=True)  # For testnet


def _cleanup_providers_redis_sessions():
    remove_providers_session()


def init_scheduler():
    # initialize the scheduler
    scheduler = BackgroundScheduler()

    # add necessary jobs
    if int(Config.PROVIDER_SYNC_INTERVAL) > 0:
        scheduler.add_job(func=_refresh_providers, trigger="interval", seconds=int(Config.PROVIDER_SYNC_INTERVAL))

    if int(Config.REMOVE_SESSION_INTERVAL) > 0:
        scheduler.add_job(func=_cleanup_providers_redis_sessions, trigger="interval",
                          seconds=int(Config.REMOVE_SESSION_INTERVAL))

    # start the scheduler
    scheduler.start()

    # at exit, shutdown the scheduler
    atexit.register(lambda: scheduler.shutdown())
