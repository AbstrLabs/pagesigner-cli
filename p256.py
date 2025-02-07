import collections



EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

p1=2**256 - 2**224 + 2**192 + 2**96 - 1 

curve = EllipticCurve(
    'P-256',
    # Field characteristic.
    p=p1,
    # Curve coefficients.
    a=-3,
    b=41058363725152142129326129780047268409114441015993725554835256314039467401291,
    # Base point.
    g=(48439561293906451759052585252797914202762949526041747995844080717082404635286,
       36134250956749795798585127919587881956611106672985015071877198253568414405109),
    # Subgroup order.
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    # Subgroup cofactor.
    h=1,
)


	




# Modular arithmetic ##########################################################


def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points #########################################


    
def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0 


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)
    # print("!!!",m*m)
    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p, -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        print('noooo')
        return None

    if k < 0:
        # k * point = -k * (-point)
        print('no')
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result

def scalar_mult2(k, point):
    table = [[0, 0] for i in range(256)]
    table[0][0] = point[0]
    table[0][1] = point[1]
    for i in range(1,256):
        pt = point_add((table[i-1][0], table[i-1][1]), (table[i-1][0], table[i-1][1]))
        table[i][0] = pt[0]
        table[i][1] = pt[1]
        print(i, hex(table[i][0]), hex(table[i][1]))
    kbits = bin(k)[2:]
    if len(kbits) < 256:
        kbits = '0'*(256-len(kbits)) + kbits
    kbits = list(reversed(kbits))
    # print(kbits) 
    init = False
    p_x, p_y = None, None
    for i in range(256):
        if kbits[i] == '1':
            if init:
                r = point_add((p_x, p_y), (table[i][0], table[i][1]))
                p_x, p_y = r
            else:
                init = True
                p_x, p_y = table[i][0], table[i][1]
            print('p_x', i, hex(p_x), 'p_y', hex(p_y))
    print(hex(p_x))
    print(hex(p_y))
    return p_x,p_y



def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result
