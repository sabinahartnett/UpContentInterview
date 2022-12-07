import datetime


def parse_date_time(dt):
    if not dt:
        return None
    return datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S%z")