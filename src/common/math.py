import math

__all__ = [
    name for name in globals()
    if not name.startswith("_")
    and callable(globals()[name])
]


def is_prime(n: int) -> bool:
    """Check if a number is prime."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def is_allmost_prime(n: int) -> bool:
    """Check if a number is almost prime (product of two primes)."""
    count = 0
    for i in range(2, int(math.sqrt(n)) + 1):
        while n % i == 0:
            n //= i
            count += 1
            if count > 2:
                return False
    if n > 1:
        count += 1
    return count == 2


def print_matrix(M) -> None:
    """get a 2D list and print it in a readable format"""
    print(f"Matrix M: {M}")
    for i in range(len(M)):
        for j in range(len(M[i])):
            print(f"M[{i}][{j}] = {M[i][j]}")


def print_tuples(tup) -> None:
    """Print each item in a tuple on a new line, along with the entire tuple."""    
    for item in tup:
        print(f"item: {item}")
    print(tup)


def control_digit(id_num: int) -> str:
    """input: 8-digit string, output: control digit as string"""
    assert isinstance(id_num, str) and len(id_num) == 8

    total = 0
    for i in range(8):
        val = int(id_num[i])
        if i % 2 == 0:       
            total += val
        else:              
            if val < 5:
                total += 2 * val
            else:
                total += ((2 * val) % 10) + 1 
                                         
    total = total % 10           
    check_digit = (10 - total) % 10

    return str(check_digit)


def audit_ID(IDNumber: str) -> bool:
    """Check if the ID number is valid."""
    if len(IDNumber) != 9:
        return False
    if not IDNumber[:-1].isdigit() or not IDNumber[-1].isdigit():
        return False
    audit_digit = control_digit(IDNumber)
    return audit_digit == int(IDNumber[-1])
