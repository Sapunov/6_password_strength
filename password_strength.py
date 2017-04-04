import getpass
import string
import requests
import requests_cache


# Expire after 30 days
requests_cache.install_cache('.cache', expire_after=60 * 60 * 24 * 30)

SETTINGS = {
    "checks": {
        "blacklist": {
            "blacklist_url": "https://raw.githubusercontent.com/" \
                "danielmiessler/SecLists/master/Passwords/10k_most_common.txt",
            "weight": 5,
            "error_msg": "!! Изменить его так как используется известный пароль"
        },
        "numbers": {
            "weight": 1,
            "error_msg": "Добавить цифры"
        },
        "upper": {
            "weight": 1,
            "error_msg": "Добавить буквы в верхнем регистре"
        },
        "lower": {
            "weight": 1,
            "error_msg": "Добавить буквы в нижнем регистре"
        },
        "spec_symbols": {
            "weight": 1,
            "error_msg": "Добавить специальные символы"
        },
        "length": {
            "ok_length": 8,
            "weight": 2,
            "error_msg": "Увеличить длину пароля"
        }
    }
}


class BlacklistError(Exception):
    pass


def check_lower(password):

    params = SETTINGS["checks"]["lower"]

    alph = set(string.ascii_lowercase + "абвгдеёжзийклмнопрстуфхцчшщьыъэюя")
    password = set(password)

    if len(password - alph) != len(password):
        return params["weight"], None
    else:
        return 0, params["error_msg"]


def check_upper(password):

    params = SETTINGS["checks"]["upper"]

    alph = set(string.ascii_uppercase + "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЬЫЪЭЮЯ")
    password = set(password)

    if len(password - alph) != len(password):
        return params["weight"], None
    else:
        return 0, params["error_msg"]


def check_numbers(password):

    params = SETTINGS["checks"]["numbers"]

    alph = set(string.digits)
    password = set(password)

    if len(password - alph) != len(password):
        return params["weight"], None
    else:
        return 0, params["error_msg"]


def check_spec_symbols(password):

    params = SETTINGS["checks"]["spec_symbols"]

    alph = set("~!@#$%^&*()_+=-\\|/{}[]`.,")
    password = set(password)

    if len(password - alph) != len(password):
        return params["weight"], None
    else:
        return 0, params["error_msg"]


def check_blacklist(password):

    params = SETTINGS["checks"]["blacklist"]

    try:
        res = requests.get(params["blacklist_url"])
    except requests.RequestException as e:
        raise BlacklistError(e)

    if res.status_code != 200:
        raise BlacklistError("Status code: %s", res.status_code)

    passwords = [it.strip() for it in res.text.split("\n")]

    if password in passwords:
        return 0, params["error_msg"]
    else:
        return params["weight"], None


def check_length(password):

    params = SETTINGS["checks"]["length"]

    if len(password) > params["ok_length"]:
        return params["weight"] // 2, None
    elif len(password) > params["ok_length"] * 2:
        return params["weight"], None
    else:
        return 0, params["error_msg"]


def get_password_strength(password):

    checks = [
        check_blacklist(password),
        check_numbers(password),
        check_upper(password),
        check_lower(password),
        check_spec_symbols(password),
        check_length(password)
    ]

    return (
        sum([check[0] for check in checks]),
        [check[1] for check in checks if check[1]]
    )


def main():

    password = getpass.getpass("Введите Ваш пароль: ")

    pass_strength, weaks = get_password_strength(password)

    # pass_strength may be > 10, so we need to set the upper limit
    pass_strength = pass_strength if pass_strength <= 10 else 10

    print("Сложность Вашего пароля: {0}/10".format(pass_strength))

    if weaks:
        print("\nЧто можно улучшить в Вашем пароле:")

        for weak in weaks:
            print(" - %s" % weak)


if __name__ == '__main__':
    main()
