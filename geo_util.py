__author__ = 'lionelschinckus'

from math import *

PRECISION = 10
R = 6367


def _cross(u, v):
    return {
        'x': (u['y'] * v['z']) - (u['z'] * v['y']),
        'y': (u['z'] * v['x']) - (u['x'] * v['z']),
        'z': (u['x'] * v['y']) - (u['y'] * v['x']),
    }


def _scale(v, factor):
    return {
        'x': v['x'] * factor,
        'y': v['y'] * factor,
        'z': v['z'] * factor,
    }


def haversine(a, b):
    """
    Calculate the great circle distance between two points
    on the earth (specified in decimal degrees)
    """
    lon1, lat1, lon2, lat2 = map(radians, [a['longitude'], a['latitude'], b['longitude'], b['latitude']])
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    km = R * c
    return km


def to_cartesian(latitude, longitude):
    """

    """
    x = R * cos(latitude) * cos(longitude)
    y = R * cos(latitude) * sin(longitude)
    z = R * sin(latitude)
    return {'x': x, 'y': y, 'z': z}


def from_cartesian(a):
    """
        a is a cartesian coordinates array [x, y, z]
    """
    latitude = asin(a['z'] / R)
    longitude = atan2(a['y'], a['x'])
    return {'latitude': latitude, 'longitude': longitude}


def nearest_point_great_circle(a, b, c):
    """

    """
    d = to_cartesian(a['latitude'], a['longitude'])
    e = to_cartesian(b['latitude'], b['longitude'])
    f = to_cartesian(c['coords']['latitude'], c['coords']['longitude'])

    g = _cross(d, e)
    h = _cross(f, g)
    t = _scale(_cross(g, h), R)
    return from_cartesian(t)


def on_segment(a, b, t):
    """

    """
    return abs(haversine(a, b) - haversine(a, t) - haversine(b, t)) < PRECISION


def nearest_point_segment(a, b, c):
    """

    """
    t = nearest_point_great_circle(a, b, c)
    if on_segment(a, b, t):
        return t
    return a if haversine(a, c) < haversine(b, c) else c
