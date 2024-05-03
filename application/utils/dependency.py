import base64

from fastapi import Header, status, HTTPException
import jwt
from jwt import ExpiredSignatureError

from application.config.config import Config
from application.utils.logger import log


def verify_token(authorization: str = Header(...)):
    try:
        assert authorization is not None and authorization != "", \
            "Authorization token in header must not be null or empty"

        if "Bearer" in authorization or "bearer" in authorization:
            authorization = authorization.split(" ")[1]

        headers = jwt.get_unverified_header(authorization)
        algo = headers["alg"]
        if algo != "RS256":
            log.error(f"Algorithm does not match.")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized.")

        # construct the public key
        public_key = base64.b64decode(Config.PUBLIC_KEY)

        # verify the signature
        jwt_token = jwt.decode(authorization, public_key, algorithms=["RS256"],
                               audience=Config.HOST_NAME, issuer=Config.SECURITY_HOST)
        if not jwt_token:
            log.error("Signature verification failed.")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized.")
        log.info("Authentication done successfully.")

        address = jwt_token['sub']
        return address
    except AssertionError as ae:
        log.error(f"Error: {ae}, Token: {authorization}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Unauthorized.")
    except ExpiredSignatureError as ese:
        log.error(f"Error: {ese}, Token: {authorization}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"{ese}")
    except Exception as e:
        log.error(f"Error: {e}, Token: {authorization}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Unauthorized.")
