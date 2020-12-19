#!/usr/bin/env python3
import pydest
import asyncio


platforms = {'XBOX': 1, 'PLAYSTATION': 2, 'PC': 3}

async def main():
    """You will need to add your api key!"""
    destiny = pydest.Pydest('0ec20be77ac249838fa84fd6fc1806df')


    platform = 3
    while not platform:
        user_input = input('Enter your platform (xbox, playstation, or pc): ')
        if user_input.upper() in platforms.keys():
            platform = platforms.get(user_input.upper())
        else:
            print('Invalid platform.')

    username = input('Enter the username to locate: ')
    res = await destiny.api.search_destiny_player(platform, username)

    if res['ErrorCode'] == 1 and len(res['Response']) > 0:
        print("---")
        print("Player found!")
        print(res)
        for result in res['Response']:
            print("Display Name: {}".format(res['Response'][0]['displayName']))
            print("Membership ID: {}".format(res['Response'][0]['membershipId']))
    else:
        print("Could not locate player.")

    await destiny.close()

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
