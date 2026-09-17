"""Bonus: estimate sequential offline guessing from a measured verification time."""

import argparse

SECONDS_PER_YEAR = 365.25 * 24 * 60 * 60


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("seconds_per_guess", type=float)
    parser.add_argument("--alphabet", type=int, default=62)
    parser.add_argument("--length", type=int, default=8)
    arguments = parser.parse_args()
    if arguments.seconds_per_guess <= 0:
        raise SystemExit("seconds_per_guess must be greater than zero")
    password_space = arguments.alphabet ** arguments.length
    guesses_per_second = 1 / arguments.seconds_per_guess
    average_seconds = password_space / (2 * guesses_per_second)
    worst_seconds = password_space / guesses_per_second
    print("Password space:", password_space)
    print("Measured sequential guesses/second:", f"{guesses_per_second:.4f}")
    print("Average sequential years:", f"{average_seconds / SECONDS_PER_YEAR:.2f}")
    print("Worst-case sequential years:", f"{worst_seconds / SECONDS_PER_YEAR:.2f}")
    print("Limitation: this CPU estimate is not a measured GPU attack rate.")


if __name__ == "__main__":
    main()
