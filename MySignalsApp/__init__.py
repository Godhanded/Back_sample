from flask_limiter.util import get_remote_address
from MySignalsApp.config import App_Config
from binance.spot import Spot
from binance.um_futures import UMFutures
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_session import Session
from flask_admin import Admin
from flask_limiter import Limiter
from flask import Flask, session
from flask_caching import Cache
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_cors import CORS
from dotenv import load_dotenv
import json
import logging
from logging.handlers import RotatingFileHandler
import os

load_dotenv(".env")

db = SQLAlchemy()

bcrypt = Bcrypt()

sess = Session()

mail = Mail()

cache = Cache()

admin = Admin(name="MySignalsApp", template_mode="bootstrap3")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour", "3 per second"],
    storage_uri=os.environ.get("REDIS"),
)

handler = RotatingFileHandler("logs/app.log", maxBytes=10000, backupCount=1)
formatter = logging.Formatter("[%(asctime)s] %(levelname)s : %(message)s ")
handler.setFormatter(formatter)
handler.setLevel(logging.ERROR)


def create_app(config_class=App_Config):
    """
    Create a new instance of the app with the given configuration.

    :param config_class: configuration class
    :return: app
    """
    # Initialize Flask-
    app = Flask(__name__)
    app.config["SESSION_SQLALCHEMY"] = db
    app.config.from_object(App_Config)
    # Initialize CORS
    CORS(app, supports_credentials=True)
    # Initialize SQLAlchemy
    db.init_app(app)
    # Initialize Flask-Mail
    mail.init_app(app)
    # Initialize Bcrypt
    bcrypt.init_app(app)
    # Initialize Flask-Session
    sess.init_app(app)
    migrate = Migrate(app, db)
    # Initialize cache
    cache.init_app(app)
    # Initialize Admin
    admin.init_app(app)

    from MySignalsApp.main.routes import main
    from MySignalsApp.auth.routes import auth
    from MySignalsApp.provider.routes import provider
    from MySignalsApp.registrar.routes import registrar
    from MySignalsApp.errors.handlers import error

    app.register_blueprint(main)
    app.register_blueprint(auth)

    app.register_blueprint(provider)
    app.register_blueprint(registrar)
    app.register_blueprint(error)

    from MySignalsApp.model_views.admin_views import model_views

    admin.add_views(*model_views)

    # Initialize rate limiter
    limiter.init_app(app)
    limiter.limit("25/second", override_defaults=True)(admin.index_view.blueprint)

    app.logger.addHandler(handler)

    # with app.app_context():
    #     db.create_all()

    set_precision(get_exchange_info())

    return app


def get_contract_details():
    with open("MySignalsApp/contract_details.json") as f:
        data = json.load(f)
    return data["address"], data["abi"]


def set_precision(exchange_info):
    (spot_, futures_) = exchange_info
    for f_info in futures_:
        cache.set(f'futures_prec_{f_info["symbol"]}', f_info["minQty"])
    for s_info in spot_:
        cache.set(f'spot_prec_{s_info["symbol"]}', s_info["minQty"])


@cache.memoize(timeout=2629746)  # 1 month
def get_exchange_info():
    spot_client = Spot()
    futures_client = UMFutures()

    spt_info = spot_client.exchange_info(permissions=["SPOT"])["symbols"]
    futr_info = futures_client.exchange_info()["symbols"]

    spot_ = [
        {
            "symbol": symbol["symbol"],
            "minQty": [
                filter_class["minQty"]
                for filter_class in symbol["filters"]
                if filter_class["filterType"] == "LOT_SIZE"
            ][0],
        }
        for symbol in spt_info
        if symbol["quoteAsset"] == "USDT"
    ]

    futures_ = [
        {
            "symbol": symbol["symbol"],
            "minQty": [
                filter_class["minQty"]
                for filter_class in symbol["filters"]
                if filter_class["filterType"] == "LOT_SIZE"
            ][0],
        }
        for symbol in futr_info
        if symbol["quoteAsset"] == "USDT"
    ]

    return (spot_, futures_)


contract_address, abi = get_contract_details()
