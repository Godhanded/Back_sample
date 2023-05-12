from pydantic import BaseModel,constr,EmailStr,validator,ValidationError


class RegisterScheme(BaseModel):
    email:EmailStr
    user_name:constr(to_lower=True,max_length=345,min_length=1)
    password:constr(max_length=64,min_length=8)
    confirm_password:constr(max_length=64,min_length=8)
    api_key:constr(max_length=100)
    api_secret:constr(max_length=100)

    @validator("email")
    def valid_email_length(cls, v):
        if len(v) > 345 :
            raise ValueError
        return v

    @validator("confirm_password")
    def passwords_are_same(cls,v,values):
        if v != values["password"]:
            raise ValueError("Passwords do not match")
        return v

class LoginScheme(BaseModel):
    user_name_or_mail:str
    password:str

class UpdateKeysSchema(BaseModel):
    api_key:constr(max_length=100)
    api_secret:constr(max_length=100)

class ValidEmailSchema(BaseModel):
    email:EmailStr

    @validator("email")
    def valid_email_length(cls, v):
        if len(v) > 345 :
            raise ValueError
        return v

class Spotschema(BaseModel):
    symbol:constr(max_length=12)
    side:constr(max_length=4)
    quantity:float
    price:float
    sl:float
    tp:float

    @validator("side")
    def is_buy_or_sell(cls,v):
        if v not in ["BUY","SELL"]:
            raise ValueError
        return v