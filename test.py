# mypackage/example.py

from typing import List

class Calculator:
    """Classe représentant une calculatrice simple.

    Fournit des méthodes pour additionner, soustraire et calculer des statistiques simples.
    """

    def __init__(self, name: str) -> None:
        """Initialise la calculatrice avec un nom.

        Args:
            name: Le nom de la calculatrice.
        """
        self.name = name

    def add(self, a: float, b: float) -> float:
        """Additionne deux nombres.

        Args:
            a: Premier nombre.
            b: Deuxième nombre.

        Returns:
            La somme de `a` et `b`.
        """
        return a + b

    def subtract(self, a: float, b: float) -> float:
        """Soustrait deux nombres.

        Args:
            a: Premier nombre.
            b: Deuxième nombre.

        Returns:
            La différence `a - b`.
        """
        return a - b

    def mean(self, numbers: List[float]) -> float:
        """Calcule la moyenne d'une liste de nombres.

        Args:
            numbers: Liste de nombres.

        Returns:
            La moyenne des nombres.
        """
        if not numbers:
            raise ValueError("La liste ne doit pas être vide")
        return sum(numbers) / len(numbers)


def greet_user(username: str) -> str:
    """Retourne un message de bienvenue personnalisé.

    Args:
        username: Le nom de l'utilisateur.

    Returns:
        Un message de bienvenue.
    """
    return f"Bonjour {username}, bienvenue sur notre calculatrice !"


if __name__ == "__main__":
    calc = Calculator("MaSuperCalc")
    print(greet_user("Alice"))
    print("3 + 5 =", calc.add(3, 5))
    print("10 - 4 =", calc.subtract(10, 4))
    print("Moyenne [1, 2, 3, 4] =", calc.mean([1, 2, 3, 4]))
