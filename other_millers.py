import random
import sys


def millersTest(d, n):
    a = 2 + random.randint(1, n - 4)

    x = pow(a, d, n)

    if (x == 1 or x == n - 1):
        return True

    while(d != n - 1):
        x = (x * x) % n
        d *= 2

        if x == 1:
            return False
        if (x == n - 1):
            return True

    return False


def isPrime(n, k):
    if (n <= 1 or n == 4):
        return False
    if (n <= 3):
        return True

    d = n - 1
    while(d % 2 == 0):
        d //= 2

    for i in range(k):
        if (millersTest(d, n) == False):
            return False

    return True


def main(argv):
    k = 10
    n = int(argv[0])
    # print("All primes smaller than:", n)
    # for i in range(1, n):
    if (isPrime(n, k)):
        # print(n, "is most likely prime", end=" ")
        return True
    else:
        # print(n, "is not prime")
        return False


if __name__ == "__main__":
    main(sys.argv[1:])
