# This file contains methods to deal with anonymising images.
#
# Contents being anonymised can be found at: https://github.com/checkpoint-restore/criu/issues/360
#
# Inorder to anonymise the image files three steps are followed:
#    - decode the binary image to json
#    - strip the necessary information from the json dict
#    - encode the json dict back to a binary image, which is now anonymised

import sys
import json
import random

def files_anon(image):
    levels = {}

    for e in image['entries']:
        f_path = e['reg']['name']
        f_path = f_path.split('/')

        lev_num = 0
        for p in f_path:
            if p == '':
                continue
            if lev_num in levels.keys():
                if p not in levels[lev_num].keys():
                    temp = list(p)
                    random.shuffle(temp)
                    levels[lev_num][p] = ''.join(temp)
            else:
                levels[lev_num] = {}
                temp = list(p)
                random.shuffle(temp)
                levels[lev_num][p] = ''.join(temp)
            lev_num += 1
        
    for i, e in enumerate(image['entries']):
        f_path = e['reg']['name']
        if f_path == '/':
            continue
        f_path = f_path.split('/')

        lev_num = 0
        for j, p in enumerate(f_path):
            if p == '':
                continue
            f_path[j] = levels[lev_num][p]
            lev_num += 1
        f_path = '/'.join(f_path)
        image['entries'][i]['reg']['name'] = f_path
    
    return image
        



anonymizers = {
    'FILES': files_anon,
    }

def anon_handler(image, magic):
    if magic != 'FILES':
        return -1
    handler = anonymizers[magic]
    anon_image = handler(image)
    return anon_image