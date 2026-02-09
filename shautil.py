#!/usr/bin/env python

import argparse
from passlib.hash import sha512_crypt


parser = argparse.ArgumentParser()

parser.add_argument('--salt', 
                    type=str,
                    help="Salt Value")

parser.add_argument('--rounds', 
                    type=int,
                    help="Iteration Count Rounds",
                    default=5000)

parser.add_argument('--password',
                    type=str,
                    help="Password",
                    default="")

parser.add_argument('--pvd',
                    type=str,
                    help="PVD - typically an /etc/shadow file")

args = vars(parser.parse_args())


local_hash = sha512_crypt.using(salt=args['salt'],
                         rounds=args['rounds']).hash(args['password'])
print("Yielded Local Hash:" , local_hash)

with open(args['pvd']) as f:
    contents = f.readlines()
    for line in contents:
        user_entry = line.split(':')
        user_map = dict(username = user_entry[0],
                        hash_value = user_entry[1],
                        unix_uid = user_entry[2],
                        unix_gid = user_entry[3],
                        display_name = user_entry[4],
                        home_path = user_entry[5],
                        login_shell = user_entry[6])
        if local_hash == user_map['hash_value']:
            print("Username: ", user_map['username'])
            print("Hash Value: ", user_map['hash_value']) 
            print("Password: ", args['password'])

print("Complete! If no user info was printed, no matches.")



