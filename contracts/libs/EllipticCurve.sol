pragma solidity >=0.8.0;

/**
 * @title   EllipticCurve
 *
 * @author  Tilman Drerup;
 *
 * @notice  Implements elliptic curve math; Parametrized for SECP256R1.
 *
 *          Includes components of code by Andreas Olofsson, Alexander Vlasov
 *          (https://github.com/BANKEX/CurveArithmetics), and Avi Asayag
 *          (https://github.com/orbs-network/elliptic-curve-solidity)
 *
 * @dev     NOTE: To disambiguate public keys when verifying signatures, activate
 *          condition 'rs[1] > lowSmax' in validateSignature().
 */
contract EllipticCurve {
    // Set parameters for curve.
    uint256 public constant a = 0;
    uint256 public constant aa = 0;
    uint256 public constant b = 7;
    uint256 public constant gx =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant gy =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant p =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant pp =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    uint256 public constant n =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    uint256 constant lowSmax =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // Pre-computed constant for 2 ** 255
    uint256 private constant U255_MAX_PLUS_1 =
        57896044618658097711785492504343953926634992332820282019728792003956564819968;

    function invMod(uint256 _x, uint256 _pp) internal pure returns (uint256) {
        require(_x != 0 && _x != _pp && _pp != 0, "Invalid number");
        uint256 q = 0;
        uint256 newT = 1;
        uint256 r = _pp;
        uint256 t;
        while (_x != 0) {
            t = r / _x;
            (q, newT) = (newT, addmod(q, (_pp - mulmod(t, newT, _pp)), _pp));
            (r, _x) = (_x, r - t * _x);
        }

        return q;
    }

    /// @dev Modular exponentiation, b^e % _pp.
    /// Source: https://github.com/androlo/standard-contracts/blob/master/contracts/src/crypto/ECCMath.sol
    /// @param _base base
    /// @param _exp exponent
    /// @param _pp modulus
    /// @return r such that r = b**e (mod _pp)
    function expMod(
        uint256 _base,
        uint256 _exp,
        uint256 _pp
    ) internal pure returns (uint256) {
        require(_pp != 0, "Modulus is zero");

        if (_base == 0) return 0;
        if (_exp == 0) return 1;

        uint256 r = 1;
        uint256 bit = U255_MAX_PLUS_1;
        assembly {
            for {

            } gt(bit, 0) {

            } {
                r := mulmod(
                    mulmod(r, r, _pp),
                    exp(_base, iszero(iszero(and(_exp, bit)))),
                    _pp
                )
                r := mulmod(
                    mulmod(r, r, _pp),
                    exp(_base, iszero(iszero(and(_exp, div(bit, 2))))),
                    _pp
                )
                r := mulmod(
                    mulmod(r, r, _pp),
                    exp(_base, iszero(iszero(and(_exp, div(bit, 4))))),
                    _pp
                )
                r := mulmod(
                    mulmod(r, r, _pp),
                    exp(_base, iszero(iszero(and(_exp, div(bit, 8))))),
                    _pp
                )
                bit := div(bit, 16)
            }
        }

        return r;
    }

    /// @dev Converts a point (x, y, z) expressed in Jacobian coordinates to affine coordinates (x', y', 1).
    /// @param _x coordinate x
    /// @param _y coordinate y
    /// @param _z coordinate z
    /// @param _pp the modulus
    /// @return (x', y') affine coordinates
    function toAffine(
        uint256 _x,
        uint256 _y,
        uint256 _z,
        uint256 _pp
    ) internal pure returns (uint256, uint256) {
        uint256 zInv = invMod(_z, _pp);
        uint256 zInv2 = mulmod(zInv, zInv, _pp);
        uint256 x2 = mulmod(_x, zInv2, _pp);
        uint256 y2 = mulmod(_y, mulmod(zInv, zInv2, _pp), _pp);

        return (x2, y2);
    }

    /// @dev Derives the y coordinate from a compressed-format point x [[SEC-1]](https://www.secg.org/SEC1-Ver-1.0.pdf).
    /// @param _prefix parity byte (0x02 even, 0x03 odd)
    /// @param _x coordinate x
    /// @param _aa constant of curve
    /// @param _bb constant of curve
    /// @param _pp the modulus
    /// @return y coordinate y
    function deriveY(
        uint8 _prefix,
        uint256 _x,
        uint256 _aa,
        uint256 _bb,
        uint256 _pp
    ) internal pure returns (uint256) {
        require(
            _prefix == 0x02 || _prefix == 0x03,
            "Invalid compressed EC point prefix"
        );

        // x^3 + ax + b
        uint256 y2 = addmod(
            mulmod(_x, mulmod(_x, _x, _pp), _pp),
            addmod(mulmod(_x, _aa, _pp), _bb, _pp),
            _pp
        );
        y2 = expMod(y2, (_pp + 1) / 4, _pp);
        // uint256 cmp = yBit ^ y_ & 1;
        uint256 y = (y2 + _prefix) % 2 == 0 ? y2 : _pp - y2;

        return y;
    }

    /// @dev Check whether point (x,y) is on curve defined by a, b, and _pp.
    /// @param _x coordinate x of P1
    /// @param _y coordinate y of P1
    /// @param _aa constant of curve
    /// @param _bb constant of curve
    /// @param _pp the modulus
    /// @return true if x,y in the curve, false else
    function isOnCurve(
        uint _x,
        uint _y,
        uint _aa,
        uint _bb,
        uint _pp
    ) internal pure returns (bool) {
        if (0 == _x || _x >= _pp || 0 == _y || _y >= _pp) {
            return false;
        }
        // y^2
        uint lhs = mulmod(_y, _y, _pp);
        // x^3
        uint rhs = mulmod(mulmod(_x, _x, _pp), _x, _pp);
        if (_aa != 0) {
            // x^3 + a*x
            rhs = addmod(rhs, mulmod(_x, _aa, _pp), _pp);
        }
        if (_bb != 0) {
            // x^3 + a*x + b
            rhs = addmod(rhs, _bb, _pp);
        }

        return lhs == rhs;
    }

    /// @dev Calculate inverse (x, -y) of point (x, y).
    /// @param _x coordinate x of P1
    /// @param _y coordinate y of P1
    /// @param _pp the modulus
    /// @return (x, -y)
    function ecInv(
        uint256 _x,
        uint256 _y,
        uint256 _pp
    ) internal pure returns (uint256, uint256) {
        return (_x, (_pp - _y) % _pp);
    }

    /// @dev Add two points (x1, y1) and (x2, y2) in affine coordinates.
    /// @param _x1 coordinate x of P1
    /// @param _y1 coordinate y of P1
    /// @param _x2 coordinate x of P2
    /// @param _y2 coordinate y of P2
    /// @param _aa constant of the curve
    /// @param _pp the modulus
    /// @return (qx, qy) = P1+P2 in affine coordinates
    function ecAdd(
        uint256 _x1,
        uint256 _y1,
        uint256 _x2,
        uint256 _y2,
        uint256 _aa,
        uint256 _pp
    ) internal pure returns (uint256, uint256) {
        uint x = 0;
        uint y = 0;
        uint z = 0;

        // Double if x1==x2 else add
        if (_x1 == _x2) {
            // y1 = -y2 mod p
            if (addmod(_y1, _y2, _pp) == 0) {
                return (0, 0);
            } else {
                // P1 = P2
                (x, y, z) = jacDouble(_x1, _y1, 1, _aa, _pp);
            }
        } else {
            (x, y, z) = jacAdd(_x1, _y1, 1, _x2, _y2, 1, _pp);
        }
        // Get back to affine
        return toAffine(x, y, z, _pp);
    }

    /// @dev Substract two points (x1, y1) and (x2, y2) in affine coordinates.
    /// @param _x1 coordinate x of P1
    /// @param _y1 coordinate y of P1
    /// @param _x2 coordinate x of P2
    /// @param _y2 coordinate y of P2
    /// @param _aa constant of the curve
    /// @param _pp the modulus
    /// @return (qx, qy) = P1-P2 in affine coordinates
    function ecSub(
        uint256 _x1,
        uint256 _y1,
        uint256 _x2,
        uint256 _y2,
        uint256 _aa,
        uint256 _pp
    ) internal pure returns (uint256, uint256) {
        // invert square
        (uint256 x, uint256 y) = ecInv(_x2, _y2, _pp);
        // P1-square
        return ecAdd(_x1, _y1, x, y, _aa, _pp);
    }

    /// @dev Multiply point (x1, y1, z1) times d in affine coordinates.
    /// @param _k scalar to multiply
    /// @param _x coordinate x of P1
    /// @param _y coordinate y of P1
    /// @param _aa constant of the curve
    /// @param _pp the modulus
    /// @return (qx, qy) = d*P in affine coordinates
    function ecMul(
        uint256 _k,
        uint256 _x,
        uint256 _y,
        uint256 _aa,
        uint256 _pp
    ) internal pure returns (uint256, uint256) {
        // Jacobian multiplication
        (uint256 x1, uint256 y1, uint256 z1) = jacMul(_k, _x, _y, 1, _aa, _pp);
        // Get back to affine
        return toAffine(x1, y1, z1, _pp);
    }

    /// @dev Adds two points (x1, y1, z1) and (x2 y2, z2).
    /// @param _x1 coordinate x of P1
    /// @param _y1 coordinate y of P1
    /// @param _z1 coordinate z of P1
    /// @param _x2 coordinate x of square
    /// @param _y2 coordinate y of square
    /// @param _z2 coordinate z of square
    /// @param _pp the modulus
    /// @return (qx, qy, qz) P1+square in Jacobian
    function jacAdd(
        uint256 _x1,
        uint256 _y1,
        uint256 _z1,
        uint256 _x2,
        uint256 _y2,
        uint256 _z2,
        uint256 _pp
    ) internal pure returns (uint256, uint256, uint256) {
        if (_x1 == 0 && _y1 == 0) return (_x2, _y2, _z2);
        if (_x2 == 0 && _y2 == 0) return (_x1, _y1, _z1);

        // We follow the equations described in https://pdfs.semanticscholar.org/5c64/29952e08025a9649c2b0ba32518e9a7fb5c2.pdf Section 5
        uint[4] memory zs; // z1^2, z1^3, z2^2, z2^3
        zs[0] = mulmod(_z1, _z1, _pp);
        zs[1] = mulmod(_z1, zs[0], _pp);
        zs[2] = mulmod(_z2, _z2, _pp);
        zs[3] = mulmod(_z2, zs[2], _pp);

        // u1, s1, u2, s2
        zs = [
            mulmod(_x1, zs[2], _pp),
            mulmod(_y1, zs[3], _pp),
            mulmod(_x2, zs[0], _pp),
            mulmod(_y2, zs[1], _pp)
        ];

        // In case of zs[0] == zs[2] && zs[1] == zs[3], double function should be used
        require(
            zs[0] != zs[2] || zs[1] != zs[3],
            "Use jacDouble function instead"
        );

        uint[4] memory hr;
        //h
        hr[0] = addmod(zs[2], _pp - zs[0], _pp);
        //r
        hr[1] = addmod(zs[3], _pp - zs[1], _pp);
        //h^2
        hr[2] = mulmod(hr[0], hr[0], _pp);
        // h^3
        hr[3] = mulmod(hr[2], hr[0], _pp);
        // qx = -h^3  -2u1h^2+r^2
        uint256 qx = addmod(mulmod(hr[1], hr[1], _pp), _pp - hr[3], _pp);
        qx = addmod(qx, _pp - mulmod(2, mulmod(zs[0], hr[2], _pp), _pp), _pp);
        // qy = -s1*z1*h^3+r(u1*h^2 -x^3)
        uint256 qy = mulmod(
            hr[1],
            addmod(mulmod(zs[0], hr[2], _pp), _pp - qx, _pp),
            _pp
        );
        qy = addmod(qy, _pp - mulmod(zs[1], hr[3], _pp), _pp);
        // qz = h*z1*z2
        uint256 qz = mulmod(hr[0], mulmod(_z1, _z2, _pp), _pp);
        return (qx, qy, qz);
    }

    /// @dev Doubles a points (x, y, z).
    /// @param _x coordinate x of P1
    /// @param _y coordinate y of P1
    /// @param _z coordinate z of P1
    /// @param _aa the a scalar in the curve equation
    /// @param _pp the modulus
    /// @return (qx, qy, qz) 2P in Jacobian
    function jacDouble(
        uint256 _x,
        uint256 _y,
        uint256 _z,
        uint256 _aa,
        uint256 _pp
    ) internal pure returns (uint256, uint256, uint256) {
        if (_z == 0) return (_x, _y, _z);

        // We follow the equations described in https://pdfs.semanticscholar.org/5c64/29952e08025a9649c2b0ba32518e9a7fb5c2.pdf Section 5
        // Note: there is a bug in the paper regarding the m parameter, M=3*(x1^2)+a*(z1^4)
        // x, y, z at this point represent the squares of _x, _y, _z
        uint256 x = mulmod(_x, _x, _pp); //x1^2
        uint256 y = mulmod(_y, _y, _pp); //y1^2
        uint256 z = mulmod(_z, _z, _pp); //z1^2

        // s
        uint s = mulmod(4, mulmod(_x, y, _pp), _pp);
        // m
        uint m = addmod(
            mulmod(3, x, _pp),
            mulmod(_aa, mulmod(z, z, _pp), _pp),
            _pp
        );

        // x, y, z at this point will be reassigned and rather represent qx, qy, qz from the paper
        // This allows to reduce the gas cost and stack footprint of the algorithm
        // qx
        x = addmod(mulmod(m, m, _pp), _pp - addmod(s, s, _pp), _pp);
        // qy = -8*y1^4 + M(S-T)
        y = addmod(
            mulmod(m, addmod(s, _pp - x, _pp), _pp),
            _pp - mulmod(8, mulmod(y, y, _pp), _pp),
            _pp
        );
        // qz = 2*y1*z1
        z = mulmod(2, mulmod(_y, _z, _pp), _pp);

        return (x, y, z);
    }

    /// @dev Multiply point (x, y, z) times d.
    /// @param _d scalar to multiply
    /// @param _x coordinate x of P1
    /// @param _y coordinate y of P1
    /// @param _z coordinate z of P1
    /// @param _aa constant of curve
    /// @param _pp the modulus
    /// @return (qx, qy, qz) d*P1 in Jacobian
    function jacMul(
        uint256 _d,
        uint256 _x,
        uint256 _y,
        uint256 _z,
        uint256 _aa,
        uint256 _pp
    ) internal pure returns (uint256, uint256, uint256) {
        // Early return in case that `_d == 0`
        if (_d == 0) {
            return (_x, _y, _z);
        }

        uint256 remaining = _d;
        uint256 qx = 0;
        uint256 qy = 0;
        uint256 qz = 1;

        // Double and add algorithm
        while (remaining != 0) {
            if ((remaining & 1) != 0) {
                (qx, qy, qz) = jacAdd(qx, qy, qz, _x, _y, _z, _pp);
            }
            remaining = remaining / 2;
            (_x, _y, _z) = jacDouble(_x, _y, _z, _aa, _pp);
        }
        return (qx, qy, qz);
    }

    /**
     * @dev Inverse of u in the field of modulo m.
     */
    function inverseMod(uint256 u, uint256 m) internal pure returns (uint256) {
        if (u == 0 || u == m || m == 0) return 0;
        if (u > m) u = u % m;

        int256 t1;
        int256 t2 = 1;
        uint256 r1 = m;
        uint256 r2 = u;
        uint256 q;

        while (r2 != 0) {
            q = r1 / r2;
            unchecked {
                (t1, t2, r1, r2) = (t2, t1 - int256(q) * t2, r2, r1 - q * r2);
            }
        }

        if (t1 < 0) return (m - uint256(-t1));

        return uint256(t1);
    }

    /**
     * @dev Transform affine coordinates into projective coordinates.
     */
    function toProjectivePoint(
        uint256 x0,
        uint256 y0
    ) public pure returns (uint256[3] memory P) {
        P[2] = addmod(0, 1, p);
        P[0] = mulmod(x0, P[2], p);
        P[1] = mulmod(y0, P[2], p);
    }

    /**
     * @dev Add two points in affine coordinates and return projective point.
     */
    function addAndReturnProjectivePoint(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) public pure returns (uint256[3] memory P) {
        uint256 x;
        uint256 y;
        (x, y) = add(x1, y1, x2, y2);
        P = toProjectivePoint(x, y);
    }

    /**
     * @dev Transform from projective to affine coordinates.
     */
    function toAffinePoint(
        uint256 x0,
        uint256 y0,
        uint256 z0
    ) public pure returns (uint256 x1, uint256 y1) {
        uint256 z0Inv;
        z0Inv = inverseMod(z0, p);
        x1 = mulmod(x0, z0Inv, p);
        y1 = mulmod(y0, z0Inv, p);
    }

    /**
     * @dev Return the zero curve in projective coordinates.
     */
    function zeroProj() public pure returns (uint256 x, uint256 y, uint256 z) {
        return (0, 1, 0);
    }

    /**
     * @dev Return the zero curve in affine coordinates.
     */
    function zeroAffine() public pure returns (uint256 x, uint256 y) {
        return (0, 0);
    }

    /**
     * @dev Check if the curve is the zero curve.
     */
    function isZeroCurve(
        uint256 x0,
        uint256 y0
    ) public pure returns (bool isZero) {
        if (x0 == 0 && y0 == 0) {
            return true;
        }
        return false;
    }

    /**
     * @dev Check if a point in affine coordinates is on the curve.
     */
    function isOnCurve(uint256 x, uint256 y) public pure returns (bool) {
        if (0 == x || x == p || 0 == y || y == p) {
            return false;
        }

        uint256 LHS = mulmod(y, y, p); // y^2
        uint256 RHS = mulmod(mulmod(x, x, p), x, p); // x^3

        if (a != 0) {
            RHS = addmod(RHS, mulmod(x, a, p), p); // x^3 + a*x
        }
        if (b != 0) {
            RHS = addmod(RHS, b, p); // x^3 + a*x + b
        }

        return LHS == RHS;
    }

    /**
     * @dev Double an elliptic curve point in projective coordinates. See
     * https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates
     */
    function twiceProj(
        uint256 x0,
        uint256 y0,
        uint256 z0
    ) public pure returns (uint256 x1, uint256 y1, uint256 z1) {
        uint256 t;
        uint256 u;
        uint256 v;
        uint256 w;

        if (isZeroCurve(x0, y0)) {
            return zeroProj();
        }

        u = mulmod(y0, z0, p);
        u = mulmod(u, 2, p);

        v = mulmod(u, x0, p);
        v = mulmod(v, y0, p);
        v = mulmod(v, 2, p);

        x0 = mulmod(x0, x0, p);
        t = mulmod(x0, 3, p);

        z0 = mulmod(z0, z0, p);
        z0 = mulmod(z0, a, p);
        t = addmod(t, z0, p);

        w = mulmod(t, t, p);
        x0 = mulmod(2, v, p);
        w = addmod(w, p - x0, p);

        x0 = addmod(v, p - w, p);
        x0 = mulmod(t, x0, p);
        y0 = mulmod(y0, u, p);
        y0 = mulmod(y0, y0, p);
        y0 = mulmod(2, y0, p);
        y1 = addmod(x0, p - y0, p);

        x1 = mulmod(u, w, p);

        z1 = mulmod(u, u, p);
        z1 = mulmod(z1, u, p);
    }

    /**
     * @dev Add two elliptic curve points in projective coordinates. See
     * https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates
     */
    function addProj(
        uint256 x0,
        uint256 y0,
        uint256 z0,
        uint256 x1,
        uint256 y1,
        uint256 z1
    ) public pure returns (uint256 x2, uint256 y2, uint256 z2) {
        uint256 t0;
        uint256 t1;
        uint256 u0;
        uint256 u1;

        if (isZeroCurve(x0, y0)) {
            return (x1, y1, z1);
        } else if (isZeroCurve(x1, y1)) {
            return (x0, y0, z0);
        }

        t0 = mulmod(y0, z1, p);
        t1 = mulmod(y1, z0, p);

        u0 = mulmod(x0, z1, p);
        u1 = mulmod(x1, z0, p);

        if (u0 == u1) {
            if (t0 == t1) {
                return twiceProj(x0, y0, z0);
            } else {
                return zeroProj();
            }
        }

        (x2, y2, z2) = addProj2(mulmod(z0, z1, p), u0, u1, t1, t0);
    }

    /**
     * @dev Helper function that splits addProj to avoid too many local variables.
     */
    function addProj2(
        uint256 v,
        uint256 u0,
        uint256 u1,
        uint256 t1,
        uint256 t0
    ) private pure returns (uint256 x2, uint256 y2, uint256 z2) {
        uint256 u;
        uint256 u2;
        uint256 u3;
        uint256 w;
        uint256 t;

        t = addmod(t0, p - t1, p);
        u = addmod(u0, p - u1, p);
        u2 = mulmod(u, u, p);

        w = mulmod(t, t, p);
        w = mulmod(w, v, p);
        u1 = addmod(u1, u0, p);
        u1 = mulmod(u1, u2, p);
        w = addmod(w, p - u1, p);

        x2 = mulmod(u, w, p);

        u3 = mulmod(u2, u, p);
        u0 = mulmod(u0, u2, p);
        u0 = addmod(u0, p - w, p);
        t = mulmod(t, u0, p);
        t0 = mulmod(t0, u3, p);

        y2 = addmod(t, p - t0, p);

        z2 = mulmod(u3, v, p);
    }

    /**
     * @dev Add two elliptic curve points in affine coordinates.
     */
    function add(
        uint256 x0,
        uint256 y0,
        uint256 x1,
        uint256 y1
    ) public pure returns (uint256, uint256) {
        uint256 z0;

        (x0, y0, z0) = addProj(x0, y0, 1, x1, y1, 1);

        return toAffinePoint(x0, y0, z0);
    }

    /**
     * @dev Double an elliptic curve point in affine coordinates.
     */
    function twice(
        uint256 x0,
        uint256 y0
    ) public pure returns (uint256, uint256) {
        uint256 z0;

        (x0, y0, z0) = twiceProj(x0, y0, 1);

        return toAffinePoint(x0, y0, z0);
    }

    /**
     * @dev Multiply an elliptic curve point by a 2 power base (i.e., (2^exp)*P)).
     */
    function multiplyPowerBase2(
        uint256 x0,
        uint256 y0,
        uint256 exp
    ) public pure returns (uint256, uint256) {
        uint256 base2X = x0;
        uint256 base2Y = y0;
        uint256 base2Z = 1;

        for (uint256 i = 0; i < exp; i++) {
            (base2X, base2Y, base2Z) = twiceProj(base2X, base2Y, base2Z);
        }

        return toAffinePoint(base2X, base2Y, base2Z);
    }

    /**
     * @dev Multiply an elliptic curve point by a scalar.
     */
    function multiplyScalar(
        uint256 x0,
        uint256 y0,
        uint256 scalar
    ) public pure returns (uint256 x1, uint256 y1) {
        if (scalar == 0) {
            return zeroAffine();
        } else if (scalar == 1) {
            return (x0, y0);
        } else if (scalar == 2) {
            return twice(x0, y0);
        }

        uint256 base2X = x0;
        uint256 base2Y = y0;
        uint256 base2Z = 1;
        uint256 z1 = 1;
        x1 = x0;
        y1 = y0;

        if (scalar % 2 == 0) {
            x1 = y1 = 0;
        }

        scalar = scalar >> 1;

        while (scalar > 0) {
            (base2X, base2Y, base2Z) = twiceProj(base2X, base2Y, base2Z);

            if (scalar % 2 == 1) {
                (x1, y1, z1) = addProj(base2X, base2Y, base2Z, x1, y1, z1);
            }

            scalar = scalar >> 1;
        }

        return toAffinePoint(x1, y1, z1);
    }

    /**
     * @dev Multiply the curve's generator point by a scalar.
     */
    function multipleGeneratorByScalar(
        uint256 scalar
    ) public pure returns (uint256, uint256) {
        return multiplyScalar(gx, gy, scalar);
    }

    /**
     * @dev Validate combination of message, signature, and public key.
     */
    function validateSignature(
        bytes32 message,
        uint256[2] memory rs,
        uint256[2] memory Q
    ) public pure returns (bool) {
        // To disambiguate between public key solutions, include comment below.
        if (rs[0] == 0 || rs[0] >= n || rs[1] == 0) {
            // || rs[1] > lowSmax)
            return false;
        }
        if (!isOnCurve(Q[0], Q[1])) {
            return false;
        }

        uint256 x1;
        uint256 x2;
        uint256 y1;
        uint256 y2;

        uint256 sInv = inverseMod(rs[1], n);
        (x1, y1) = multiplyScalar(gx, gy, mulmod(uint256(message), sInv, n));
        (x2, y2) = multiplyScalar(Q[0], Q[1], mulmod(rs[0], sInv, n));
        uint256[3] memory P = addAndReturnProjectivePoint(x1, y1, x2, y2);

        if (P[2] == 0) {
            return false;
        }

        uint256 Px = inverseMod(P[2], p);
        Px = mulmod(P[0], mulmod(Px, Px, p), p);

        return Px % n == rs[0];
    }

    function decomposeKey(
        bytes memory data
    ) public pure returns (uint256 x, uint256 y) {
        // bytes32 x;
        // bytes32 y;
        assembly {
            x := mload(add(data, 0x20))
            y := mload(add(data, 0x40))
        }
        // return (uint256(x), uint256(y));
    }
}
