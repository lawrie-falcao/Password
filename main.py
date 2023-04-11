import hashlib

while True:
    password = input("Entrer un mot de passe :")

    if len(password) < 8:
        print("Le mot de passe doit contenir au moins 8 caractères.")
        continue

    if not any(char.isupper() for char in password):
        print("Le mot de passe doit contenir au moins une lettre majuscule.")
        continue

    if not any(char.islower() for char in password):
        print("Le mot de passe doit contenir au moins une lettre minuscule.")
        continue

    if not any(char.isdigit() for char in password):
        print("Le mot de passe doit contenir au moins un chiffre.")
        continue

    if not any(char in "!@#$%^&*" for char in password):
        print("Le mot de passe doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
        continue

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    print("Mot de passe valide.")
    print("Mot de passe crypté avec SHA-256 :", hashed_password)
    break
