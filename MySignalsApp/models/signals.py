from sqlalchemy.dialects.postgresql import JSON
from MySignalsApp.models.base import BaseModel
from MySignalsApp import db, admin
from flask import session, flash
from flask_admin.contrib.sqla import ModelView


class Signal(BaseModel):
    __tablename__ = "signals"

    id = db.Column(db.Integer(), primary_key=True, unique=True, nullable=False)
    signal = db.Column(JSON, nullable=False)
    is_spot = db.Column(db.Boolean(), nullable=False, default=True)
    status = db.Column(db.Boolean(), nullable=False, default=False)
    provider = db.Column(db.String(34), db.ForeignKey("users.id"), nullable=False)
    placed_signals = db.Relationship(
        "PlacedSignals", backref="signal", lazy=True, cascade="all, delete-orphan"
    )

    def __init__(self, signal, status, provider, is_spot=True):
        self.signal = signal
        self.status = status
        self.provider = provider
        self.is_spot = is_spot

    def __repr__(self):
        return f"id({self.id}), signal({self.signal}), status({self.status}), date_created({self.date_created}), provider({self.user.user_name}), provider_id({self.provider}))"

    def __str__(self):
        return f"{self.signal}"

    def format(self):
        return {
            "id": self.id,
            "signal": self.signal,
            "status": self.status,
            "is_spot": self.is_spot,
            "provider": self.user.user_name,
            "provider_wallet": self.user.wallet,
            "date_created": self.date_created,
        }


class SignalModelView(ModelView):
    def is_accessible(self):
        user = session.get("user") if session else None
        return "Registrar" in user.get("permission") if user else False

    # def _handle_view(self, name, **kwargs):
    #     print(self.is_accessible())
    #     if not self.is_accessible():
    #         return self.render("admin/login.html")
    #     else:
    #         return self.render("admin/index.html")

    def inaccessible_callback(self, name, **kwargs):
        flash("you are not authorized", category="error")
        return self.render("admin/login.html")

    can_create = False
    column_searchable_list = ["provider"]
    column_filters = ["is_spot", "status"]
    column_list = ("id", "signal", "is_spot", "status", "user", "date_created")
    form_columns = ("signal", "status", "provider", "date_created")


admin.add_view(SignalModelView(Signal, db.session))
