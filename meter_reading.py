import argparse
import datetime
import logging
import pickle
import signal
import sys
from threading import Event
from time import sleep
from typing import Union

import pytz
import requests
from dateutil import parser as dtparser

BASE_URL = "https://www.smartmetertexas.com"

AUTH_ENDPOINT = BASE_URL + "/commonapi/user/authenticate"
METER_ENDPOINT = BASE_URL + "/api/meter"
OD_READ_ENDPOINT = BASE_URL + "/api/ondemandread"
INTERVAL_ENDPOINT = BASE_URL + "/api/usage/interval"
READING_DAILY_ENDPOINT = BASE_URL + "/api/usage/daily"
LATEST_OD_READ_ENDPOINT = BASE_URL + "/api/usage/latestodrread"

USERNAME = "UTDRMAC"
PASSWORD = "Zs7xXcSfx8Zl"
ESIID = "1008901010186208720100"
METER_ID = "61356255"
ODR_SLEEP = 15

# Strange behavior with timezones if used directly; extract the tzinfo instead
CENTRAL_TIMEZONE = datetime.datetime.now(tz=pytz.timezone("US/Central")).tzinfo

# Influx stuff
INFLUX_URL = "http://10.10.10.203:8086/api/v2/write?org=home_metrics&bucket=home_metrics&precision=s"
INFLUX_METRIC = "ElectricMeter"
INFLUX_INTERVALMETRIC = "ElectricMeterInterval"
INFLUX_HEADERS = {
    "Authorization": "Token TlCW_yKtzMJDzOuv-mculCfuGZXRxOCfSDutdTRObwayBNsp623IMtHyiObbNRQAjwYUttkeXhj-f_pzt4FUBA==",
}

# Global token object
TOKEN = {
    "token": "",
    "expires": datetime.datetime.now(tz=CENTRAL_TIMEZONE),
    "next_daily_sync": 0,
}

# Catch docker sigterm during sleep()
EXIT = Event()

#
# Parse args
#
parser = argparse.ArgumentParser(prog="meter_reading.py")
parser.add_argument("--debug", default=False, action="store_true")
parser.add_argument("--start", help="Get historical meter readings starting on this MM/DD/YYYY")
parser.add_argument("--end", help="Get historical meter readings ending on this MM/DD/YYYY")

args = parser.parse_args()

# Logging
LOG_LEVEL = "INFO"
if args.debug:
    LOG_LEVEL = "DEBUG"

FORMAT = "%(asctime)s %(funcName)-20s %(levelname)-7s %(message)s"
logging.basicConfig(format=FORMAT, stream=sys.stdout, level=LOG_LEVEL)
logging.Formatter.converter = lambda *_: datetime.datetime.now(tz=CENTRAL_TIMEZONE).timetuple()

_LOGGER = logging.getLogger(__name__)

TOO_MANY_ODR_HOUR = 5031
TOO_MANY_ODR_DAY = 5032

#
# Funcs
#

def get_meters(s: requests.sessions.Session) -> None:

    json_response = client_request(s, METER_ENDPOINT, json={"esiid": "*"})
    for meter_data in json_response["data"]:
        _LOGGER.info(f"{meter_data['address']} {meter_data['esiid']} {meter_data['esiid']}")


def get_15min(s: requests.sessions.Session, ts: datetime.datetime = None) -> list:
    # Get the interval data to parse out consumed, and surplus generation

    retry = 1
    maxretries = 3

    while retry < maxretries:
        try:
            tsStr = ts.strftime("%m/%d/%Y")
            payload = {
                "startDate": tsStr,
                "endDate": tsStr,
                "esiid": ESIID,
            }
            _LOGGER.info(f"get_15min data for {tsStr} with {payload}")

            json_response = client_request(s, INTERVAL_ENDPOINT, json=payload)
            _LOGGER.debug(f"Raw interval data: {json_response}")

            data = json_response["intervaldata"]

            if len(data) == 0:
                _LOGGER.info(f"No energy data for {tsStr}; going back 1 day")
                ts = ts - datetime.timedelta(days=1)
                continue

        except Exception as e:
            msg = f"Error reading 15m data: {e}"
            _LOGGER.error(msg)
            raise SmartMeterTexasAPIError(msg) from e

        # We have data; process it
        """Example entry
        {
            "starttime": " 12:00 am",
            "endtime": " 12:15 am",
            "date": "2024-04-22",
            "consumption": 0.088,
            "consumption_est_act": "A",
            "generation": 0,
            "generation_est_act": null
        }
        """

        energyData = []
        for entry in data:
            entryTs = dtparser.parse(f"{entry['date']}{entry['endtime']}").replace(
                tzinfo=CENTRAL_TIMEZONE,
            )

            # The last entry should be "tomorrow's" starting value, but the date
            # still shows "today". Fix by adding 1 day.
            if entry["endtime"] == " 12:00 am":
                entryTs = entryTs + datetime.timedelta(days=1)

            energyData.append([entryTs, entry["consumption"]])

        return energyData

    # Too many retries
    return None


def get_daily(s: requests.sessions.Session, ts: datetime.datetime) -> dict:

    payload = {
        "esiid": ESIID,
        "startDate": ts.strftime("%m/%d/%Y"),
        "endDate": ts.strftime("%m/%d/%Y"),
    }

    try:
        json_response = client_request(s, READING_DAILY_ENDPOINT, json=payload)

        _LOGGER.debug(f"Daily reading data: {json_response}")

        data = json_response["dailyData"]

        if len(data) == 0:
            return None

        if len(data) > 1:
            raise SmartMeterTexasAPIError("Too many data points returned")

        data = data[0]

    except KeyError as k:
        msg = f"Error reading daily data: {json_response}"
        _LOGGER.error(msg)
        raise SmartMeterTexasAPIError(msg) from k
    else:
        dt = dtparser.parse(f"{data['date']} {data['starttime']}").replace(
            tzinfo=CENTRAL_TIMEZONE,
        )
        daily_reading = {
            "timestamp": dt,
            "startreading": float(data["startreading"]),
            "endreading": float(data["endreading"]),
            "usage": float(data["reading"]),
        }

        _LOGGER.info(f"Daily reading for {daily_reading['timestamp']}")
        _LOGGER.info(f" | Starting: {daily_reading['startreading']}")
        _LOGGER.info(f" | Ending: {daily_reading['endreading']}")
        _LOGGER.info(f" | Usage: {daily_reading['usage']}")

        return daily_reading


def ondemand_request(s: requests.sessions.Session, ts: datetime.datetime) -> datetime.datetime:

    # Submit ODR request
    payload = {"ESIID": ESIID, "MeterNumber": METER_ID}
    json_response = client_request(s, OD_READ_ENDPOINT, json=payload)
    _LOGGER.debug(f"ODR Request response: {json_response}")

    data = json_response["data"]
    code = int(data["statusCode"])

    if code == TOO_MANY_ODR_HOUR:
        _LOGGER.error("Too many ODR requests this hour")
        curMinute = (ts.minute * -1)
        ts += datetime.timedelta(hours=1, minutes=curMinute)
        return ts

    if code == TOO_MANY_ODR_DAY:
        _LOGGER.error("Too many ODR requests today")
        curHour = (ts.hour * -1)
        curMinute = (ts.minute * -1)
        ts += datetime.timedelta(days=1, hours=curHour, minutes=curMinute)
        return ts

    if code == 0:
        _LOGGER.info("ODR request submitted successfully")

    return ts


def ondemand_status(s: requests.sessions.Session, ts: datetime.datetime) -> datetime.datetime:

    # Poll for reading
    payload = {"ESIID": ESIID}
    maxretries = 6
    retries = 0

    while retries < maxretries:
        try:
            json_response = client_request(s, LATEST_OD_READ_ENDPOINT, json=payload)
            _LOGGER.debug(f"ODR status response: {json_response}")

            data = json_response["data"]
            status = data["odrstatus"]
            odrTs = dtparser.parse(f"{data['odrdate']}").replace(tzinfo=CENTRAL_TIMEZONE)

        except KeyError:
            _LOGGER.error(
                f"Error reading ODR response: {json_response}; Attempt {retries}/6",
            )
            retries += 1
            sleep(ODR_SLEEP)
            continue
        except Exception:
            raise

        # No exception, check result
        if status == "COMPLETED":
            odrRead = data["odrread"]

            odrTsStr = odrTs.strftime("%m/%d/%y %H:%M:%S")
            _LOGGER.info(f"ODR reading completed: {odrTsStr} / {odrRead}")

            # post to Influx
            logReading(
                int(odrTs.timestamp()), 0, odrRead, INFLUX_INTERVALMETRIC,
            )

            # If it has been more than 1 hour since the last ODR,
            # make a new request
            now = datetime.datetime.now(tz=CENTRAL_TIMEZONE)
            if now - odrTs > datetime.timedelta(hours=1):
                _LOGGER.info("More than 1hr since last ODR; Requesting new ODR...")
                return ondemand_request(s, ts)

            # If last ODR was from previous hour, make a new request
            if odrTs.hour == (now.hour - 1):
                _LOGGER.info("Last ODR took place in previous hour block; Requesting new ODR for this hour...")
                return ondemand_request(s, ts)

            # We cannot do another ODR until the next hour.
            negMinutes = (odrTs.minute * -1)
            odrTs += datetime.timedelta(hours=1, minutes=negMinutes)

            return odrTs

        if status == "PENDING":
            _LOGGER.info(f"ODR pending; Sleeping for {ODR_SLEEP}; Attempt {retries}/6")

        elif status is None:
            _LOGGER.info("No ODR status data found; Requesting ODR")
            # A request will either: fail in two ways, or succeed.
            # On fail, we receive a modified timestamp for the next iteration
            # On success, the timestamp is unmodified which will cause another
            # read loop.
            return ondemand_request(s, ts)

        elif status in ("T-FAILED", "FAILED"):
            """
            Error:
            {
             'odrstatus': 'T-FAILED',
             'odrread': None,
             'odrusage': None,
             'odrdate': '05/27/2024 00:22:50',
             'responseMessage': 'SUCCESS'}
            """
            _LOGGER.error("Internal error from ODR; Sleeping 5m")
            odrTs += datetime.timedelta(minutes=5)

            return odrTs

        else:
            _LOGGER.error(f"Unknown ODR status {data}; Attempt {retries}/6")

        # PENDING or else
        retries += 1
        sleep(ODR_SLEEP)

    # Exited the loop
    raise SmartMeterTexasException("Failed after 6 attempts to get ODR status")


def client_request(s: requests.sessions.Session, path: str, **kwargs: dict) -> dict:
    now = datetime.datetime.now(tz=CENTRAL_TIMEZONE)
    token_expires = get_token("expires")
    token_token = get_token("token")

    """ _LOGGER.debug(f"Now: {now} | Token Expires: {token_expires}")"""

    # If token expired, or non-existent
    if token_token == "" or now > token_expires:
        token_refresh(s)

    resp = s.post(path, **kwargs)

    if resp.status_code == requests.codes.UNAUTHORIZED:
        _LOGGER.warning("Authentication token expired; Refreshing...")
        update_token("expires", token_expires - datetime.timedelta(minutes=30))
        raise SmartMeterTexasAuthExpired("Authentication token expired")

    if resp.status_code == requests.codes.FORBIDDEN:
        raise SmartMeterTexasAPIError("Reached ratelimit or brute force protection")

    if resp.status_code == requests.codes.METHOD_NOT_ALLOWED:
        _LOGGER.debug(resp.content)
        raise SmartMeterTexasAPIError

    if resp.status_code != requests.codes.OK:
        _LOGGER.error(f"Status Code: {resp.status_code}")
        _LOGGER.error(resp.content)
        msg = f"Unknown error for '{path}'"
        raise SmartMeterTexasException(msg)

    # Since API call did not return a 400 code, update the token_expiration.
    update_token("expires", now + datetime.timedelta(minutes=10))

    return resp.json()


def token_refresh(s: requests.sessions.Session) -> None:
    _LOGGER.info("Refreshing token...")

    # POST login
    payload = {
        "username": USERNAME,
        "password": PASSWORD,
        "rememberMe": "true",
    }

    resp = s.post(AUTH_ENDPOINT, json=payload)

    if resp.status_code == requests.codes.BAD_REQUEST:
        raise SmartMeterTexasAPIError("Username or password was not accepted")

    if resp.status_code == requests.codes.FORBIDDEN:
        raise SmartMeterTexasAPIError("Reached ratelimit or brute force protection")

    if resp.status_code != requests.codes.OK:
        _LOGGER.error(f"Status Code: {resp.status_code}")
        _LOGGER.error(resp.content)
        raise SmartMeterTexasException("Unknown error during login")

    json_response = resp.json()

    # Get session token
    token_token = json_response["token"]
    token_expires = datetime.datetime.now(
        tz=CENTRAL_TIMEZONE,
    ) + datetime.timedelta(minutes=10)

    update_token("token", token_token, save = False)
    update_token("expires", token_expires)

    _LOGGER.info(f"Token refreshed; Expires {token_expires}")

    # Update headers with fresh token, or loaded token
    s.headers.update({"Authorization": f"Bearer {token_token}"})


def do_daily_intervals(s: requests.sessions.Session, dailyIntervalTs: datetime.datetime = None) -> bool:

    _LOGGER.info(f"Getting daily interval data for {dailyIntervalTs.date()}")

    latest_reading = get_daily(s, dailyIntervalTs)

    if latest_reading is None:
        _LOGGER.info(
            f"No daily reading for {dailyIntervalTs.date()}; Try again later",
        )
        return False

    # Got data, process it
    readingDt = latest_reading["timestamp"]
    currentReading = latestStartReading = latest_reading["startreading"]
    latestEndReading = latest_reading["endreading"]

    # Post the starting value of the previous day to Influx
    logReading(int(readingDt.timestamp()), 0, latestStartReading)

    #
    # Get 15min interval data and merge with latest end of day
    # to generate actual meter readings
    #
    intervals = get_15min(s, dailyIntervalTs)

    if len(intervals) == 0:
        _LOGGER.error(f"No intervals found for {dailyIntervalTs}; Try again later")
        return False

    _LOGGER.info(f"Starting: {readingDt} | {latestStartReading}")

    # Adding each interval value to the starting reading value should result
    # in equaling the end reading
    for d in intervals:
        ts = d[0]
        utcTs = int(ts.timestamp())
        consumption = d[1]
        currentReading = round(currentReading + consumption, 3)

        _LOGGER.info(
            f"Consumption: {ts} | {consumption} | Current: {currentReading}",
        )

        logReading(utcTs, consumption, currentReading)

    _LOGGER.info(f"Ending: {readingDt} | {latestEndReading}")

    # Successfully fetched data
    return True


def do_historical(s: requests.sessions.Session, startstr: str, endstr: str) -> None:

    # Parse starting and ending
    try:
        current = datetime.datetime.strptime(startstr, "%m/%d/%Y")
        end = datetime.datetime.strptime(endstr, "%m/%d/%Y")
    except Exception:
        _LOGGER.error(f"Unable to parse '{startstr}' / '{endstr}' timestamp")
        sys.exit(1)

    # Loop through the dates
    while current < end:
        ok = do_daily_intervals(s, current)
        if not ok:
            _LOGGER.error(f"Did not fetch any data for {current}; continuing...")

        current = current + datetime.timedelta(days=1)
        sleep(10)

    _LOGGER.info("Finished historical import")


def get_token(k: str) -> Union[str, datetime.datetime]:
    return TOKEN[k]

def update_token(k: str, v: Union[str, datetime.datetime], save: bool = True) -> None:
    TOKEN[k] = v
    if save:
        with open("token", "wb") as f:
            pickle.dump(TOKEN, f)


#
# Main
#
def main() -> None:

    global TOKEN

    # Create web session
    s = requests.Session()
    s.headers.update(
        {
            "Accept-Language": "en-US,en;q=0.8",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        },
    )

    # Load saved token
    try:
        with open("token", "rb") as f:

            _LOGGER.debug("Found token file. Loading...")
            TOKEN = pickle.load(f)

            # Update headers with fresh token, or loaded token
            s.headers.update({"Authorization": f"Bearer {TOKEN['token']}"})

    except FileNotFoundError:
        _LOGGER.debug("No token file found. Continuing...")

    # Historical batch job?
    if args.start is not None:
        do_historical(s, args.start, args.end)
        sys.exit(0)

    # Catch docker kill signal
    def signaler(_x: int, _y: int) -> None:
        _LOGGER.info("-- Caught SIGTERM --")
        EXIT.set()
    signal.signal(signal.SIGTERM, signaler)

    # Timer for On-demand readings
    last_ondemand_time = datetime.datetime.now(tz=CENTRAL_TIMEZONE) - datetime.timedelta(hours=1)

    # Next daily sync yesterday, if not loading state
    next_daily_sync = get_token("next_daily_sync")
    if next_daily_sync == 0:
        next_daily_sync = datetime.datetime.now(tz=CENTRAL_TIMEZONE)

    #
    # Main loop
    #
    while not EXIT.is_set():

        _LOGGER.info("-- Main loop --")

        now = datetime.datetime.now(tz=CENTRAL_TIMEZONE)

        try:
            # Init session to server
            s.get(BASE_URL)

            """
            Get the 15min interval daily reading every 4hrs
            We know the previous days' data is not available until at least
            9AM "today", so we can skip checking between midnight and 9am
            """

            nineam = datetime.datetime.combine(now, datetime.time(9, 0)).replace(
                tzinfo=CENTRAL_TIMEZONE,
            )

            if (now > nineam):
                _LOGGER.info(f"After 9am; Now: {now} / Next daily sync: {next_daily_sync}")
                if (now > next_daily_sync):

                    previous_interval_date = next_daily_sync - datetime.timedelta(days=1)

                    ok = do_daily_intervals(s, previous_interval_date)
                    if ok:
                        next_daily_sync = datetime.datetime.combine(
                            next_daily_sync + datetime.timedelta(days=1), datetime.time(1, 0),
                        ).replace(tzinfo=CENTRAL_TIMEZONE)
                        update_token("next_daily_sync", next_daily_sync)

                        _LOGGER.info(f"Successful daily sync; Next daily sync: {next_daily_sync}")

                else:
                    _LOGGER.info("Not yet time to do_daily_intervals")

            #
            # On-demand reading
            #
            if last_ondemand_time < now:
                _LOGGER.info("Checking On-Demand Reading status...")
                last_ondemand_time = ondemand_status(s, last_ondemand_time)
            _LOGGER.info(f"Next On-Demand Reading: {last_ondemand_time}")

            # Wait 5m then loop again
            EXIT.wait(300)

        except KeyboardInterrupt:
            _LOGGER.warning("Caught shutdown")
            sys.exit(0)
        except SmartMeterTexasAuthExpired:
            # Short sleep to go back through the loop and refresh the token
            sleep(10)
        except SmartMeterTexasAPIError as f:
            _LOGGER.error(f"API Error: {f}")
            sleep(60)
        except Exception as e:
            _LOGGER.error(f"Generic exception: {e}")
            sleep(60)

    _LOGGER.info("-- Shutting down...")


def logReading(ts: datetime.datetime, consumption: int, val: int, bucket: str = INFLUX_METRIC) -> None:

    influxLogger = logging.getLogger(__name__)

    data = f"{bucket} value={val},consumption={consumption} {ts}"
    influxLogger.debug(f"Logging data {data}")

    response = requests.post(url=INFLUX_URL, headers=INFLUX_HEADERS, data=data, timeout=10)
    if response.status_code != requests.codes.NO_CONTENT:
        influxLogger.warning(f"Unable to post to influx: {response.text}")


class SmartMeterTexasException(Exception):
    ...


class SmartMeterTexasAPIError(SmartMeterTexasException):
    ...


class SmartMeterTexasAuthExpired(SmartMeterTexasAPIError):
    ...


if __name__ == "__main__":
    main()
