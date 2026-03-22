package com.alibaba.fastjson.util;

import androidx.work.WorkRequest;
import java.lang.reflect.Array;
import java.math.BigInteger;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class RyuDouble {
    private static final int[][] POW5_SPLIT = (int[][]) Array.newInstance((Class<?>) int.class, 326, 4);
    private static final int[][] POW5_INV_SPLIT = (int[][]) Array.newInstance((Class<?>) int.class, 291, 4);

    static {
        BigInteger bigInteger = BigInteger.ONE;
        BigInteger subtract = bigInteger.shiftLeft(31).subtract(bigInteger);
        BigInteger subtract2 = bigInteger.shiftLeft(31).subtract(bigInteger);
        int i2 = 0;
        while (i2 < 326) {
            BigInteger pow = BigInteger.valueOf(5L).pow(i2);
            int bitLength = pow.bitLength();
            int i3 = i2 == 0 ? 1 : (int) ((((i2 * 23219280) + 10000000) - 1) / 10000000);
            if (i3 != bitLength) {
                throw new IllegalStateException(bitLength + " != " + i3);
            }
            if (i2 < POW5_SPLIT.length) {
                for (int i4 = 0; i4 < 4; i4++) {
                    POW5_SPLIT[i2][i4] = pow.shiftRight(((3 - i4) * 31) + (bitLength - 121)).and(subtract).intValue();
                }
            }
            if (i2 < POW5_INV_SPLIT.length) {
                BigInteger bigInteger2 = BigInteger.ONE;
                BigInteger add = bigInteger2.shiftLeft(bitLength + 121).divide(pow).add(bigInteger2);
                for (int i5 = 0; i5 < 4; i5++) {
                    if (i5 == 0) {
                        POW5_INV_SPLIT[i2][i5] = add.shiftRight((3 - i5) * 31).intValue();
                    } else {
                        POW5_INV_SPLIT[i2][i5] = add.shiftRight((3 - i5) * 31).and(subtract2).intValue();
                    }
                }
            }
            i2++;
        }
    }

    public static String toString(double d2) {
        char[] cArr = new char[24];
        return new String(cArr, 0, toString(d2, cArr, 0));
    }

    public static int toString(double d2, char[] cArr, int i2) {
        int i3;
        boolean z;
        boolean z2;
        long j2;
        int i4;
        boolean z3;
        long j3;
        long j4;
        boolean z4;
        long j5;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        int i11;
        int i12;
        int i13;
        if (!Double.isNaN(d2)) {
            if (d2 == Double.POSITIVE_INFINITY) {
                int i14 = i2 + 1;
                cArr[i2] = 'I';
                int i15 = i14 + 1;
                cArr[i14] = 'n';
                int i16 = i15 + 1;
                cArr[i15] = 'f';
                int i17 = i16 + 1;
                cArr[i16] = 'i';
                int i18 = i17 + 1;
                cArr[i17] = 'n';
                int i19 = i18 + 1;
                cArr[i18] = 'i';
                int i20 = i19 + 1;
                cArr[i19] = 't';
                i9 = i20 + 1;
                cArr[i20] = 'y';
            } else if (d2 == Double.NEGATIVE_INFINITY) {
                int i21 = i2 + 1;
                cArr[i2] = '-';
                int i22 = i21 + 1;
                cArr[i21] = 'I';
                int i23 = i22 + 1;
                cArr[i22] = 'n';
                int i24 = i23 + 1;
                cArr[i23] = 'f';
                int i25 = i24 + 1;
                cArr[i24] = 'i';
                int i26 = i25 + 1;
                cArr[i25] = 'n';
                int i27 = i26 + 1;
                cArr[i26] = 'i';
                int i28 = i27 + 1;
                cArr[i27] = 't';
                i13 = i28 + 1;
                cArr[i28] = 'y';
            } else {
                long doubleToLongBits = Double.doubleToLongBits(d2);
                if (doubleToLongBits == 0) {
                    int i29 = i2 + 1;
                    cArr[i2] = '0';
                    int i30 = i29 + 1;
                    cArr[i29] = '.';
                    i13 = i30 + 1;
                    cArr[i30] = '0';
                } else if (doubleToLongBits == Long.MIN_VALUE) {
                    int i31 = i2 + 1;
                    cArr[i2] = '-';
                    int i32 = i31 + 1;
                    cArr[i31] = '0';
                    int i33 = i32 + 1;
                    cArr[i32] = '.';
                    i9 = i33 + 1;
                    cArr[i33] = '0';
                } else {
                    int i34 = (int) ((doubleToLongBits >>> 52) & 2047);
                    long j6 = doubleToLongBits & 4503599627370495L;
                    if (i34 == 0) {
                        i3 = -1074;
                    } else {
                        i3 = (i34 - 1023) - 52;
                        j6 |= 4503599627370496L;
                    }
                    boolean z5 = doubleToLongBits < 0;
                    boolean z6 = (j6 & 1) == 0;
                    long j7 = 4 * j6;
                    long j8 = 2 + j7;
                    int i35 = (j6 != 4503599627370496L || i34 <= 1) ? 1 : 0;
                    long j9 = (j7 - 1) - i35;
                    int i36 = i3 - 2;
                    if (i36 >= 0) {
                        int max = Math.max(0, ((int) ((i36 * 3010299) / 10000000)) - 1);
                        int i37 = ((((-i36) + max) + (((max == 0 ? 1 : (int) ((((max * 23219280) + 10000000) - 1) / 10000000)) + 122) - 1)) - 93) - 21;
                        if (i37 >= 0) {
                            int[] iArr = POW5_INV_SPLIT[max];
                            long j10 = j7 >>> 31;
                            long j11 = j7 & 2147483647L;
                            z2 = z5;
                            long j12 = ((((((((((((j11 * iArr[3]) >>> 31) + (iArr[2] * j11)) + (j10 * iArr[3])) >>> 31) + (iArr[1] * j11)) + (iArr[2] * j10)) >>> 31) + (iArr[0] * j11)) + (iArr[1] * j10)) >>> 21) + ((iArr[0] * j10) << 10)) >>> i37;
                            long j13 = j8 >>> 31;
                            long j14 = 2147483647L & j8;
                            long j15 = ((((((((((((iArr[3] * j14) >>> 31) + (iArr[2] * j14)) + (j13 * iArr[3])) >>> 31) + (iArr[1] * j14)) + (iArr[2] * j13)) >>> 31) + (iArr[0] * j14)) + (iArr[1] * j13)) >>> 21) + ((iArr[0] * j13) << 10)) >>> i37;
                            long j16 = j9 >>> 31;
                            long j17 = 2147483647L & j9;
                            j4 = j15;
                            z = z6;
                            j3 = ((((((((((((j17 * iArr[3]) >>> 31) + (iArr[2] * j17)) + (j16 * iArr[3])) >>> 31) + (iArr[1] * j17)) + (iArr[2] * j16)) >>> 31) + (iArr[0] * j17)) + (iArr[1] * j16)) >>> 21) + ((iArr[0] * j16) << 10)) >>> i37;
                            i4 = max;
                            if (i4 <= 21) {
                                long j18 = j7 % 5;
                                if (j18 == 0) {
                                    if (j18 != 0) {
                                        i12 = 0;
                                    } else if (j7 % 25 != 0) {
                                        i12 = 1;
                                    } else if (j7 % 125 != 0) {
                                        i12 = 2;
                                    } else if (j7 % 625 != 0) {
                                        i12 = 3;
                                    } else {
                                        long j19 = j7 / 625;
                                        i12 = 4;
                                        for (long j20 = 0; j19 > j20 && j19 % 5 == j20; j20 = 0) {
                                            j19 /= 5;
                                            i12++;
                                        }
                                    }
                                    z4 = i12 >= i4;
                                    z3 = false;
                                    j2 = j12;
                                } else if (z) {
                                    if (j9 % 5 != 0) {
                                        i11 = 0;
                                    } else if (j9 % 25 != 0) {
                                        i11 = 1;
                                    } else if (j9 % 125 != 0) {
                                        i11 = 2;
                                    } else if (j9 % 625 != 0) {
                                        i11 = 3;
                                    } else {
                                        long j21 = j9 / 625;
                                        i11 = 4;
                                        for (long j22 = 0; j21 > j22 && j21 % 5 == j22; j22 = 0) {
                                            j21 /= 5;
                                            i11++;
                                        }
                                    }
                                    if (i11 >= i4) {
                                        z3 = true;
                                        z4 = false;
                                        j2 = j12;
                                    }
                                } else {
                                    if (j8 % 5 != 0) {
                                        i10 = 0;
                                    } else if (j8 % 25 != 0) {
                                        i10 = 1;
                                    } else if (j8 % 125 != 0) {
                                        i10 = 2;
                                    } else if (j8 % 625 != 0) {
                                        i10 = 3;
                                    } else {
                                        long j23 = j8 / 625;
                                        i10 = 4;
                                        for (long j24 = 0; j23 > j24 && j23 % 5 == j24; j24 = 0) {
                                            j23 /= 5;
                                            i10++;
                                        }
                                    }
                                    if (i10 >= i4) {
                                        j4--;
                                    }
                                }
                            }
                            z3 = false;
                            z4 = false;
                            j2 = j12;
                        } else {
                            throw new IllegalArgumentException(C1499a.m626l("", i37));
                        }
                    } else {
                        z = z6;
                        z2 = z5;
                        int max2 = Math.max(0, ((int) ((r1 * 6989700) / 10000000)) - 1);
                        int i38 = (-i36) - max2;
                        int i39 = ((max2 - ((i38 == 0 ? 1 : (int) ((((i38 * 23219280) + 10000000) - 1) / 10000000)) - 121)) - 93) - 21;
                        if (i39 >= 0) {
                            int[] iArr2 = POW5_SPLIT[i38];
                            long j25 = j7 >>> 31;
                            long j26 = j7 & 2147483647L;
                            long j27 = ((((((((((((j26 * iArr2[3]) >>> 31) + (iArr2[2] * j26)) + (j25 * iArr2[3])) >>> 31) + (iArr2[1] * j26)) + (iArr2[2] * j25)) >>> 31) + (iArr2[0] * j26)) + (iArr2[1] * j25)) >>> 21) + ((iArr2[0] * j25) << 10)) >>> i39;
                            long j28 = j8 >>> 31;
                            long j29 = j8 & 2147483647L;
                            j2 = j27;
                            long j30 = ((((((((((((j29 * iArr2[3]) >>> 31) + (iArr2[2] * j29)) + (j28 * iArr2[3])) >>> 31) + (iArr2[1] * j29)) + (iArr2[2] * j28)) >>> 31) + (iArr2[0] * j29)) + (iArr2[1] * j28)) >>> 21) + ((iArr2[0] * j28) << 10)) >>> i39;
                            long j31 = j9 >>> 31;
                            long j32 = 2147483647L & j9;
                            long j33 = ((((((((((((j32 * iArr2[3]) >>> 31) + (iArr2[2] * j32)) + (j31 * iArr2[3])) >>> 31) + (iArr2[1] * j32)) + (iArr2[2] * j31)) >>> 31) + (iArr2[0] * j32)) + (iArr2[1] * j31)) >>> 21) + ((iArr2[0] * j31) << 10)) >>> i39;
                            i4 = max2 + i36;
                            if (max2 <= 1) {
                                if (z) {
                                    z3 = i35 == 1;
                                    j4 = j30;
                                } else {
                                    j4 = j30 - 1;
                                    z3 = false;
                                }
                                j3 = j33;
                                z4 = true;
                            } else if (max2 < 63) {
                                z3 = false;
                                j4 = j30;
                                z4 = (j7 & ((1 << (max2 + (-1))) - 1)) == 0;
                                j3 = j33;
                            } else {
                                z3 = false;
                                j3 = j33;
                                j4 = j30;
                                z4 = false;
                            }
                        } else {
                            throw new IllegalArgumentException(C1499a.m626l("", i39));
                        }
                    }
                    int i40 = j4 >= 1000000000000000000L ? 19 : j4 >= 100000000000000000L ? 18 : j4 >= 10000000000000000L ? 17 : j4 >= 1000000000000000L ? 16 : j4 >= 100000000000000L ? 15 : j4 >= 10000000000000L ? 14 : j4 >= 1000000000000L ? 13 : j4 >= 100000000000L ? 12 : j4 >= 10000000000L ? 11 : j4 >= 1000000000 ? 10 : j4 >= 100000000 ? 9 : j4 >= 10000000 ? 8 : j4 >= 1000000 ? 7 : j4 >= 100000 ? 6 : j4 >= WorkRequest.MIN_BACKOFF_MILLIS ? 5 : j4 >= 1000 ? 4 : j4 >= 100 ? 3 : j4 >= 10 ? 2 : 1;
                    int i41 = (i4 + i40) - 1;
                    boolean z7 = i41 < -3 || i41 >= 7;
                    if (z3 || z4) {
                        int i42 = 0;
                        int i43 = 0;
                        while (true) {
                            long j34 = j4 / 10;
                            long j35 = j3 / 10;
                            if (j34 <= j35 || (j4 < 100 && z7)) {
                                break;
                            }
                            z3 &= j3 % 10 == 0;
                            z4 &= i42 == 0;
                            i42 = (int) (j2 % 10);
                            j2 /= 10;
                            i43++;
                            j4 = j34;
                            j3 = j35;
                        }
                        if (z3 && z) {
                            while (j3 % 10 == 0 && (j4 >= 100 || !z7)) {
                                z4 &= i42 == 0;
                                i42 = (int) (j2 % 10);
                                j4 /= 10;
                                j2 /= 10;
                                j3 /= 10;
                                i43++;
                            }
                        }
                        if (z4 && i42 == 5 && j2 % 2 == 0) {
                            i42 = 4;
                        }
                        j5 = j2 + (((j2 != j3 || (z3 && z)) && i42 < 5) ? 0 : 1);
                        i5 = i43;
                    } else {
                        i5 = 0;
                        int i44 = 0;
                        while (true) {
                            long j36 = j4 / 10;
                            long j37 = j3 / 10;
                            if (j36 <= j37 || (j4 < 100 && z7)) {
                                break;
                            }
                            i44 = (int) (j2 % 10);
                            j2 /= 10;
                            i5++;
                            j4 = j36;
                            j3 = j37;
                        }
                        j5 = j2 + ((j2 == j3 || i44 >= 5) ? 1 : 0);
                    }
                    int i45 = i40 - i5;
                    if (z2) {
                        i6 = i2 + 1;
                        cArr[i2] = '-';
                    } else {
                        i6 = i2;
                    }
                    if (!z7) {
                        char c2 = '0';
                        if (i41 < 0) {
                            int i46 = i6 + 1;
                            cArr[i6] = '0';
                            int i47 = i46 + 1;
                            cArr[i46] = '.';
                            int i48 = -1;
                            while (i48 > i41) {
                                cArr[i47] = c2;
                                i48--;
                                c2 = '0';
                                i47++;
                            }
                            i7 = i47;
                            for (int i49 = 0; i49 < i45; i49++) {
                                cArr[((i47 + i45) - i49) - 1] = (char) ((j5 % 10) + 48);
                                j5 /= 10;
                                i7++;
                            }
                        } else {
                            int i50 = i41 + 1;
                            if (i50 >= i45) {
                                for (int i51 = 0; i51 < i45; i51++) {
                                    cArr[((i6 + i45) - i51) - 1] = (char) ((j5 % 10) + 48);
                                    j5 /= 10;
                                }
                                int i52 = i6 + i45;
                                while (i45 < i50) {
                                    cArr[i52] = '0';
                                    i45++;
                                    i52++;
                                }
                                int i53 = i52 + 1;
                                cArr[i52] = '.';
                                cArr[i53] = '0';
                                i7 = i53 + 1;
                            } else {
                                int i54 = i6 + 1;
                                for (int i55 = 0; i55 < i45; i55++) {
                                    if ((i45 - i55) - 1 == i41) {
                                        cArr[((i54 + i45) - i55) - 1] = '.';
                                        i54--;
                                    }
                                    cArr[((i54 + i45) - i55) - 1] = (char) ((j5 % 10) + 48);
                                    j5 /= 10;
                                }
                                i7 = i45 + 1 + i6;
                            }
                        }
                        return i7 - i2;
                    }
                    for (int i56 = 0; i56 < i45 - 1; i56++) {
                        int i57 = (int) (j5 % 10);
                        j5 /= 10;
                        cArr[(i6 + i45) - i56] = (char) (i57 + 48);
                    }
                    cArr[i6] = (char) ((j5 % 10) + 48);
                    cArr[i6 + 1] = '.';
                    int i58 = i45 + 1 + i6;
                    if (i45 == 1) {
                        cArr[i58] = '0';
                        i58++;
                    }
                    int i59 = i58 + 1;
                    cArr[i58] = 'E';
                    if (i41 < 0) {
                        cArr[i59] = '-';
                        i41 = -i41;
                        i59++;
                    }
                    if (i41 >= 100) {
                        int i60 = i59 + 1;
                        i8 = 48;
                        cArr[i59] = (char) ((i41 / 100) + 48);
                        i41 %= 100;
                        i59 = i60 + 1;
                        cArr[i60] = (char) ((i41 / 10) + 48);
                    } else {
                        i8 = 48;
                        if (i41 >= 10) {
                            cArr[i59] = (char) ((i41 / 10) + 48);
                            i59++;
                        }
                    }
                    i9 = i59 + 1;
                    cArr[i59] = (char) ((i41 % 10) + i8);
                }
            }
            return i9 - i2;
        }
        int i61 = i2 + 1;
        cArr[i2] = 'N';
        int i62 = i61 + 1;
        cArr[i61] = 'a';
        i13 = i62 + 1;
        cArr[i62] = 'N';
        return i13 - i2;
    }
}
