#!/usr/bin/env python3

import os
import requests
import getpass
import string

import cacher as cache

CACHE_LIFETIME = 60 * 60 * 24 * 90
PASSWORDS_BLACKLIST = "https://raw.githubusercontent.com/danielmiessler/SecLists/" \
    "master/Passwords/10k_most_common.txt"

PASSWORD_OK_LEN = 8
LOWERCASE = string.ascii_lowercase + "абвгдеёжзийклмнопрстуфхцчшщьыъэюя"
UPPERCASE = string.ascii_uppercase + "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЬЫЪЭЮЯ"

cache.set_cache_directory(os.path.join(os.path.dirname(__file__), ".cache"))

class BlacklistError(Exception):
    pass


def contents_lower(password):
    alph = set(LOWERCASE)
    password = set(password)

    return len(password - alph) != len(password)


def contents_upper(password):
    alph = set(UPPERCASE)
    password = set(password)

    return len(password - alph) != len(password)


def contents_numbers(password):
    alph = set(string.digits)
    password = set(password)

    return len(password - alph) != len(password)


def contents_spec_symbols(password):
    alph = set("~!@#$%^&*()_+=-\\|/{}[]`.,")
    password = set(password)

    return (password - alph) != len(password)


def in_blacklist(password):
    blacklist = cache.get("blacklist")
    if not blacklist:
        try:
            res = requests.get(PASSWORDS_BLACKLIST)
        except requests.RequestException as e:
            raise BlacklistError(e)

        if res.status_code != 200:
            raise BlacklistError("Status code: %s", res.status_code)

        passwords = [it.strip() for it in res.text.split("\n")]

        blacklist = cache.put("blacklist", passwords, CACHE_LIFETIME)

    return password in blacklist


def get_password_strength(password):
    weaks = []
    strength = 0

    if not in_blacklist(password):
        strength += 5
    else:
        weaks.append("Вы используете известный пароль! Поменяйте его")

    if contents_numbers(password):
        strength += 1
    else:
        weaks.append("Добавьте цифры")

    if contents_upper(password):
        strength += 1
    else:
        weaks.append("Добавьте буквы в верхнем регистре")

    if contents_lower(password):
        strength += 1
    else:
        weaks.append("Добавьте буквы в нижнем регистре")

    if contents_spec_symbols(password):
        strength += 1
    else:
        weaks.append("Добавьте специальные символы")

    if len(password) > PASSWORD_OK_LEN:
        strength += 1
    else:
        weaks.append("Увеличьте длину пароля")

    if len(password) >= PASSWORD_OK_LEN * 2:
        strength += 1

    return strength, weaks


def main():
    password = getpass.getpass("Введите Ваш пароль: ")

    pass_strength, weaks = get_password_strength(password)

    print("Сложность Вашего пароля: %s/10" % (pass_strength if pass_strength <= 10 else 10))

    if weaks:
        print("\nЧто можно улучшить в Вашем пароле:")

        for weak in weaks:
            print(" - %s" % weak)

if __name__ == '__main__':
    main()
