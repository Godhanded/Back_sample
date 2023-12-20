from flask_admin import BaseView, expose
from MySignalsApp import db, admin, bcrypt
from MySignalsApp.models.base import BaseModel
from flask_admin.contrib.sqla import ModelView
from wtforms import EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask import session, redirect, flash
from MySignalsApp.utils import query_one_filtered
from flask_wtf import FlaskForm
import enum


class Roles(enum.Enum):
    USER = "User"
    PROVIDER = ("User", "Provider")
    REGISTRAR = ("User", "Registrar")

    @staticmethod
    def fetch_names():
        return [c.value for c in Roles]


class User(BaseModel):
    __tablename__ = "users"

    user_name = db.Column(db.String(345), unique=True, nullable=False, index=True)
    email = db.Column(db.String(345), unique=True, nullable=False, index=True)
    password = db.Column(db.String(64), nullable=False)
    api_key = db.Column(db.String(), nullable=True)
    api_secret = db.Column(db.String(), nullable=True)
    wallet = db.Column(db.String(43), nullable=True)
    is_active = db.Column(db.Boolean(), nullable=False, default=False)
    roles = db.Column(db.Enum(Roles), nullable=False, default=Roles.USER)
    signals = db.Relationship("Signal", backref="user", lazy=True)
    placed_signals = db.Relationship("PlacedSignals", backref="user", lazy=True)
    tokens = db.Relationship(
        "UserTokens", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    def __init__(
        self,
        user_name,
        email,
        password,
        roles=Roles.USER,
        wallet="",
    ):
        self.user_name = user_name
        self.email = email
        self.password = password
        self.roles = roles
        self.wallet = wallet

    def __repr__(self):
        return f"id({self.id}), user_name({self.user_name}), email({self.email}), is_active({self.is_active}), date_created({self.date_created}))"

    def __str__(self):
        return f"{self.email}"

    def format(self):
        return {
            "id": self.id,
            "email": self.email,
            "user_name": self.user_name,
            "roles": self.roles,
            "is_active": self.is_active,
            "wallet": self.wallet,
            "has_api_keys": bool(self.api_key and self.api_secret),
            "date_created": self.date_created,
        }


class AdminForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class AdminLoginView(BaseView):
    @expose("/", methods=["GET", "POST"])
    def admin_form_login(self):
        form = AdminForm()

        if form.validate_on_submit():
            email, password = form.email.data, form.password.data
            if not email or not password:
                flash("One or more missing fields")
                return self.render("admin/login.html", category="error"), 400
            user = query_one_filtered(User, email=email)
            if not user or not bcrypt.check_password_hash(user.password, password):
                flash("Incorrect email or password", category="error")
                return self.render("admin/login.html"), 401

            session["user"] = {"id": user.id, "permission": user.roles.value}
            return redirect("/admin", 302)
        return self.render("admin/login.html", form=form)


class AdminLogoutView(BaseView):
    @expose("/")
    def logout_admin(self):
        session.pop("user", None)
        return redirect("/admin/login", 302)


class UserModelView(ModelView):
    def is_accessible(self):
        user = session.get("user") if session else None
        return "Registrar" in user.get("permission") if user else False

    # def _handle_view(self, name, **kwargs):
    #     print(self.is_accessible())
    #     if not self.is_accessible():
    #         return redirect("admin/login")
    #     else:
    #         return redirect("admin/user")

    def inaccessible_callback(self, name, **kwargs):
        flash("You are not Authorized", category="error")
        return self.render("admin/login.html")

    can_create = False
    can_delete = False
    column_searchable_list = ["user_name", "email"]
    column_filters = ["is_active", "roles"]
    column_list = (
        "id",
        "user_name",
        "email",
        "wallet",
        "is_active",
        "roles",
        "date_created",
    )
    form_columns = (
        "user_name",
        "email",
        "wallet",
        "is_active",
        "roles",
        "date_created",
    )


admin.add_view(UserModelView(User, db.session))
admin.add_view(AdminLoginView(endpoint="login", name="login"))
admin.add_view(AdminLogoutView(endpoint="logout", name="logout"))
