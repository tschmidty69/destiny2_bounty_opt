import os
import redis

class Config(object):
    API_KEY = os.environ.get('API_KEY')
    SECRET_KEY = os.environ.get('APP_SECRET_KEY') or 'Kgn239gfl^k4.<12FGGHe'
    CLIENT_ID = os.environ.get('CLIENT_ID')

    # Flask config
    SESSION_PERMANENT = True

    # Flask-Session
    SESSION_TYPE = os.environ.get('SESSION_TYPE')
    # could also have done 'url=rediss://:password@host:port/0'
    SESSION_REDIS = redis.Redis(host=os.environ.get('REDIS_HOST'),
                                port=os.environ.get('REDIS_PORT'),
                                password=os.environ.get('REDIS_PW'))

class_names = ['Titan', 'Hunter', 'Warlock']

classifications = {
    'locations': ['Cosmodrome', 'Europa', 'European Dead Zone', 'Moon', 'Nessus'],
    'sublocations': ['Cadmus Ridge', 'Aesterian Abyss'],
    'activities': ['Strike', 'Gambit', 'Crucible', 'Empire Hunt', 'Lost Sector',
                   'public events', 'patrols', 'Loot chests'],
    'weapons': ['Auto Rifle', 'Fusion Rifle', 'Linear Fusion Rifle', 'Pulse Rifle',
               'Submachine Gun', 'Machine Gun', 'Bow', 'Trace Rifle', 'Shotgun',
               'Sidearm', 'Sniper Rifles', 'Hand Cannon'],
    'weapon_types': ['Kinetic', 'Energy', 'Power', 'Void weapons', 'Arc weapons',
                     'Solar weapons', 'Special ammo', 'Primary ammo', 'Heavy ammo'],
    'precision': ['precision'],
    'finishers': ['finishers'],
    'multiple': ['multiple'],
    'rapidly': ['rapidly'],
    'ability_types': ['Super', 'Void abilities', 'Arc abilities', 'Solar abilities', 'grenades'],
    'elements': ['Solar kills', 'Arc kills', 'Void kills'],
    'enemy_races': ['Cabal', 'Fallen', 'Hive', 'Taken', 'Scorn', 'Vex'],
    'enemy_types': ['Walker', 'Captain', 'Knight', 'Acolyte', 'Ogre', 'Shrieker']
}


# A lot of these are outdated so not using them
hashes = {
    'DestinyActivityDefinition': 'activityHash',
    'DestinyActivityTypeDefinition': 'activityTypeHash',
    'DestinyClassDefinition': 'classHash',
    'DestinyGenderDefinition': 'genderHash',
    'DestinyInventoryBucketDefinition': 'bucketHash',
    'DestinyInventoryItemDefinition': 'itemHash',
    'DestinyProgressionDefinition': 'progressionHash',
    'DestinyRaceDefinition': 'raceHash',
    'DestinyTalentGridDefinition': 'gridHash',
    'DestinyUnlockFlagDefinition': 'flagHash',
    'DestinyHistoricalStatsDefinition': 'statId',
    'DestinyDirectorBookDefinition': 'bookHash',
    'DestinyStatDefinition': 'statHash',
    'DestinySandboxPerkDefinition': 'perkHash',
    'DestinyDestinationDefinition': 'destinationHash',
    'DestinyPlaceDefinition': 'placeHash',
    'DestinyActivityBundleDefinition': 'bundleHash',
    'DestinyStatGroupDefinition': 'statGroupHash',
    'DestinySpecialEventDefinition': 'eventHash',
    'DestinyFactionDefinition': 'factionHash',
    'DestinyVendorCategoryDefinition': 'categoryHash',
    'DestinyEnemyRaceDefinition': 'raceHash',
    'DestinyScriptedSkullDefinition': 'skullHash',
    'DestinyGrimoireCardDefinition': 'cardId'
}

hashes_trunc = {
    'DestinyInventoryItemDefinition': 'hash',
}
