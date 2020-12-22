import os

class Config(object):
    API_KEY = os.environ.get('API_KEY')
    SECRET_KEY = os.environ.get('APP_SECRET_KEY') or 'Kgn239gfl^k4.<12FGGHe'
    CLIENT_ID = os.environ.get('CLIENT_ID')

    # Flask config
    SESSION_PERMANENT = True

class_names = ['Titan', 'Hunter', 'Warlock']

locations = ['European Dead Zone',
             'Europa',
             'Nessus'
             ]

activities = ['strike', 'gambit', 'crucible', 'empire hunt', 'lost sector']

weapons = ['Auto Rifle', 'Fusion Rifle', 'Linear Fusion Rifle', 'Pulse Rifle',
           'Submachine Gun', 'Machine Gun', 'Bow', 'Trace Rifle', 'Shotgun',
           'Sidearm', 'Hand Cannon']

enemy_races = ['cabal', 'fallen', 'hive', 'taken', 'scorn']

enemy_types = ['walker', 'captain', 'knight', 'acolyte', 'ogre']


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
