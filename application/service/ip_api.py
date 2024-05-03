import requests

from application.exception.praetor_exception import PraetorException


def get_provider_locations(ip_address: list[str]):
    try:
        url = f"http://ip-api.com/batch?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon," \
              f"timezone,isp,org,as,hosting,query"

        response = requests.request("POST", url, json=ip_address)
        if response.status_code == 200:
            return response.json()
        else:
            raise PraetorException(response.json(), "P50024")
    except PraetorException as pe:
        raise pe
    except Exception as e:
        raise e
