from MySignalsApp.models.base import BaseModel
from MySignalsApp import db
from datetime import datetime


class PlacedSignals(BaseModel):
    __tablename__ = "placedsignals"
    id = db.Column(db.Integer(), primary_key=True, unique=True, nullable=False)
    user_id = db.Column(db.String(34), db.ForeignKey("users.id"), nullable=False)
    signal_id = db.Column(db.Integer(), db.ForeignKey("signals.id"), nullable=False)
    rating = db.Column(db.Integer(), nullable=False, default=0)

    def __init__(self, user_id, signal_id):
        self.user_id = user_id
        self.signal_id = signal_id

    def __repr__(self):
        return f"user_id({self.user_id}), signal({self.signal_id}), rating({self.rating}), date_placed {self.date_created})"


    def format(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "signal_id": self.signal_id,
            "rating": self.rating,
            "date_created": self.date_created,
        }