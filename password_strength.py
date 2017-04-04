import getpass
import string
import requests
import requests_cache


requests_cache.install_cache('.cache', expire_after=60 * 60 * 24 * 90)

PASSWORDS_BLACKLIST = "https://raw.githubusercontent.com/danielmiessler/" \
    "SecLists/master/Passwords/10k_most_common.txt"

PASSWORD_OK_LEN = 8
LOWERCASE = string.ascii_lowercase + "абвгдеёжзийклмнопрстуфхцчшщьыъэюя"
UPPERCASE = string.ascii_uppercase + "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЬЫЪЭЮЯ"
MESSAGES = [
    "Вы используете известный пароль! Поменяйте его",
    "Добавьте цифры",
    "Добавьте буквы в верхнем регистре",
    "Добавьте буквы в нижнем регистре",
    "Добавьте специальные символы",
    "Увеличьте длину пароля"
]


class BlacklistError(Exception):
    pass


def check_lower(password):

    alph = set(LOWERCASE)
    password = set(password)

    return 1 if len(password - alph) != len(password) else 0


def check_upper(password):

    alph = set(UPPERCASE)
    password = set(password)

    return 1 if len(password - alph) != len(password) else 0


def check_numbers(password):

    alph = set(string.digits)
    password = set(password)

    return 1 if len(password - alph) != len(password) else 0


def check_spec_symbols(password):

    alph = set("~!@#$%^&*()_+=-\\|/{}[]`.,")
    password = set(password)

    return 1 if (password - alph) != len(password) else 0


def check_blacklist(password):

    try:
        res = requests.get(PASSWORDS_BLACKLIST)
    except requests.RequestException as e:
        raise BlacklistError(e)

    if res.status_code != 200:
        raise BlacklistError("Status code: %s", res.status_code)

    passwords = [it.strip() for it in res.text.split("\n")]

    return 0 if password in passwords else 5


def check_length(password):

    if len(password) > PASSWORD_OK_LEN:
        return 1
    elif len(password) > PASSWORD_OK_LEN * 2:
        return 2
    else:
        return 0


def get_password_strength(password):

    weaks = []
    checks = [
        check_blacklist(password),
        check_numbers(password),
        check_upper(password),
        check_lower(password),
        check_spec_symbols(password),
        check_length(password)
    ]

    for i in range(len(checks)):
        if not checks[i]:
            weaks.append(MESSAGES[i])

    return sum(checks), weaks


def main():

    password = getpass.getpass("Введите Ваш пароль: ")

    pass_strength, weaks = get_password_strength(password)

    print("Сложность Вашего пароля: %s/10" % (
        pass_strength if pass_strength <= 10 else 10))

    if weaks:
        print("\nЧто можно улучшить в Вашем пароле:")

        for weak in weaks:
            print(" - %s" % weak)


if __name__ == '__main__':
    main()
