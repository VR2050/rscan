package com.alibaba.fastjson.util;

import com.alibaba.fastjson.asm.Label;

/* loaded from: classes.dex */
public final class RyuFloat {
    private static final int[][] POW5_SPLIT = {new int[]{Label.FORWARD_REFERENCE_TYPE_WIDE, 0}, new int[]{671088640, 0}, new int[]{838860800, 0}, new int[]{1048576000, 0}, new int[]{655360000, 0}, new int[]{819200000, 0}, new int[]{1024000000, 0}, new int[]{640000000, 0}, new int[]{800000000, 0}, new int[]{1000000000, 0}, new int[]{625000000, 0}, new int[]{781250000, 0}, new int[]{976562500, 0}, new int[]{610351562, 1073741824}, new int[]{762939453, Label.FORWARD_REFERENCE_TYPE_SHORT}, new int[]{953674316, 872415232}, new int[]{596046447, 1619001344}, new int[]{745058059, 1486880768}, new int[]{931322574, 1321730048}, new int[]{582076609, 289210368}, new int[]{727595761, 898383872}, new int[]{909494701, 1659850752}, new int[]{568434188, 1305842176}, new int[]{710542735, 1632302720}, new int[]{888178419, 1503507488}, new int[]{555111512, 671256724}, new int[]{693889390, 839070905}, new int[]{867361737, 2122580455}, new int[]{542101086, 521306416}, new int[]{677626357, 1725374844}, new int[]{847032947, 546105819}, new int[]{1058791184, 145761362}, new int[]{661744490, 91100851}, new int[]{827180612, 1187617888}, new int[]{1033975765, 1484522360}, new int[]{646234853, 1196261931}, new int[]{807793566, 2032198326}, new int[]{1009741958, 1466506084}, new int[]{631088724, 379695390}, new int[]{788860905, 474619238}, new int[]{986076131, 1130144959}, new int[]{616297582, 437905143}, new int[]{770371977, 1621123253}, new int[]{962964972, 415791331}, new int[]{601853107, 1333611405}, new int[]{752316384, 1130143345}, new int[]{940395480, 1412679181}};
    private static final int[][] POW5_INV_SPLIT = {new int[]{Label.FORWARD_REFERENCE_TYPE_SHORT, 1}, new int[]{214748364, 1717986919}, new int[]{171798691, 1803886265}, new int[]{137438953, 1013612282}, new int[]{219902325, 1192282922}, new int[]{175921860, 953826338}, new int[]{140737488, 763061070}, new int[]{225179981, 791400982}, new int[]{180143985, 203624056}, new int[]{144115188, 162899245}, new int[]{230584300, 1978625710}, new int[]{184467440, 1582900568}, new int[]{147573952, 1266320455}, new int[]{236118324, 308125809}, new int[]{188894659, 675997377}, new int[]{151115727, 970294631}, new int[]{241785163, 1981968139}, new int[]{193428131, 297084323}, new int[]{154742504, 1955654377}, new int[]{247588007, 1840556814}, new int[]{198070406, 613451992}, new int[]{158456325, 61264864}, new int[]{253530120, 98023782}, new int[]{202824096, 78419026}, new int[]{162259276, 1780722139}, new int[]{259614842, 1990161963}, new int[]{207691874, 733136111}, new int[]{166153499, 1016005619}, new int[]{265845599, 337118801}, new int[]{212676479, 699191770}, new int[]{170141183, 988850146}};

    public static String toString(float f2) {
        char[] cArr = new char[15];
        return new String(cArr, 0, toString(f2, cArr, 0));
    }

    public static int toString(float f2, char[] cArr, int i2) {
        int i3;
        boolean z;
        int i4;
        int i5;
        boolean z2;
        int i6;
        boolean z3;
        int i7;
        int i8;
        int i9;
        boolean z4;
        int i10;
        int i11;
        int i12;
        int i13;
        int i14;
        int i15;
        int i16;
        if (Float.isNaN(f2)) {
            int i17 = i2 + 1;
            cArr[i2] = 'N';
            int i18 = i17 + 1;
            cArr[i17] = 'a';
            i16 = i18 + 1;
            cArr[i18] = 'N';
        } else {
            if (f2 == Float.POSITIVE_INFINITY) {
                int i19 = i2 + 1;
                cArr[i2] = 'I';
                int i20 = i19 + 1;
                cArr[i19] = 'n';
                int i21 = i20 + 1;
                cArr[i20] = 'f';
                int i22 = i21 + 1;
                cArr[i21] = 'i';
                int i23 = i22 + 1;
                cArr[i22] = 'n';
                int i24 = i23 + 1;
                cArr[i23] = 'i';
                int i25 = i24 + 1;
                cArr[i24] = 't';
                cArr[i25] = 'y';
                return (i25 + 1) - i2;
            }
            if (f2 == Float.NEGATIVE_INFINITY) {
                int i26 = i2 + 1;
                cArr[i2] = '-';
                int i27 = i26 + 1;
                cArr[i26] = 'I';
                int i28 = i27 + 1;
                cArr[i27] = 'n';
                int i29 = i28 + 1;
                cArr[i28] = 'f';
                int i30 = i29 + 1;
                cArr[i29] = 'i';
                int i31 = i30 + 1;
                cArr[i30] = 'n';
                int i32 = i31 + 1;
                cArr[i31] = 'i';
                int i33 = i32 + 1;
                cArr[i32] = 't';
                i16 = i33 + 1;
                cArr[i33] = 'y';
            } else {
                int floatToIntBits = Float.floatToIntBits(f2);
                if (floatToIntBits != 0) {
                    if (floatToIntBits == Integer.MIN_VALUE) {
                        int i34 = i2 + 1;
                        cArr[i2] = '-';
                        int i35 = i34 + 1;
                        cArr[i34] = '0';
                        int i36 = i35 + 1;
                        cArr[i35] = '.';
                        cArr[i36] = '0';
                        return (i36 + 1) - i2;
                    }
                    int i37 = (floatToIntBits >> 23) & 255;
                    int i38 = 8388607 & floatToIntBits;
                    if (i37 == 0) {
                        i3 = -149;
                    } else {
                        i3 = (i37 - 127) - 23;
                        i38 |= 8388608;
                    }
                    boolean z5 = floatToIntBits < 0;
                    boolean z6 = (i38 & 1) == 0;
                    int i39 = i38 * 4;
                    int i40 = i39 + 2;
                    int i41 = i39 - ((((long) i38) != 8388608 || i37 <= 1) ? 2 : 1);
                    int i42 = i3 - 2;
                    if (i42 >= 0) {
                        i7 = (int) ((i42 * 3010299) / 10000000);
                        if (i7 == 0) {
                            i13 = i42;
                            i14 = 1;
                        } else {
                            i13 = i42;
                            i14 = (int) ((((i7 * 23219280) + 10000000) - 1) / 10000000);
                        }
                        int[][] iArr = POW5_INV_SPLIT;
                        long j2 = iArr[i7][0];
                        long j3 = iArr[i7][1];
                        long j4 = i39;
                        int i43 = (((i14 + 59) - 1) + ((-i13) + i7)) - 31;
                        z = z6;
                        int i44 = (int) (((j4 * j2) + ((j4 * j3) >> 31)) >> i43);
                        long j5 = i40;
                        i9 = (int) (((j5 * j2) + ((j5 * j3) >> 31)) >> i43);
                        int i45 = i40;
                        long j6 = i41;
                        int i46 = (int) (((j2 * j6) + ((j6 * j3) >> 31)) >> i43);
                        if (i7 == 0 || (i9 - 1) / 10 > i46 / 10) {
                            i15 = i46;
                            i8 = 0;
                        } else {
                            i15 = i46;
                            i8 = (int) ((((iArr[r6][0] * j4) + ((iArr[r6][1] * j4) >> 31)) >> (((r4 - 1) + (((i7 - 1 == 0 ? 1 : (int) ((((r6 * 23219280) + 10000000) - 1) / 10000000)) + 59) - 1)) - 31)) % 10);
                        }
                        int i47 = 0;
                        while (i45 > 0 && i45 % 5 == 0) {
                            i45 /= 5;
                            i47++;
                        }
                        int i48 = 0;
                        int i49 = i39;
                        while (i49 > 0 && i49 % 5 == 0) {
                            i49 /= 5;
                            i48++;
                        }
                        int i50 = 0;
                        while (i41 > 0 && i41 % 5 == 0) {
                            i41 /= 5;
                            i50++;
                        }
                        z3 = i47 >= i7;
                        z4 = i48 >= i7;
                        z2 = i50 >= i7;
                        i6 = i15;
                        i4 = i44;
                    } else {
                        z = z6;
                        int i51 = -i42;
                        int i52 = (int) ((i51 * 6989700) / 10000000);
                        int i53 = i51 - i52;
                        int i54 = i53 == 0 ? 1 : (int) ((((i53 * 23219280) + 10000000) - 1) / 10000000);
                        int[][] iArr2 = POW5_SPLIT;
                        long j7 = iArr2[i53][0];
                        long j8 = iArr2[i53][1];
                        int i55 = (i52 - (i54 - 61)) - 31;
                        long j9 = i39;
                        i4 = (int) (((j9 * j7) + ((j9 * j8) >> 31)) >> i55);
                        long j10 = i40;
                        int i56 = (int) (((j10 * j7) + ((j10 * j8) >> 31)) >> i55);
                        long j11 = i41;
                        int i57 = (int) (((j7 * j11) + ((j11 * j8) >> 31)) >> i55);
                        if (i52 == 0 || (i56 - 1) / 10 > i57 / 10) {
                            i5 = 0;
                        } else {
                            i5 = (int) ((((iArr2[r3][0] * j9) + ((iArr2[r3][1] * j9) >> 31)) >> (((i52 - 1) - ((i53 + 1 == 0 ? 1 : (int) ((((r3 * 23219280) + 10000000) - 1) / 10000000)) - 61)) - 31)) % 10);
                        }
                        int i58 = i42 + i52;
                        boolean z7 = 1 >= i52;
                        boolean z8 = i52 < 23 && (((1 << (i52 + (-1))) - 1) & i39) == 0;
                        z2 = (i41 % 2 == 1 ? 0 : 1) >= i52;
                        i6 = i57;
                        z3 = z7;
                        i7 = i58;
                        i8 = i5;
                        i9 = i56;
                        z4 = z8;
                    }
                    int i59 = 1000000000;
                    int i60 = 10;
                    while (i60 > 0 && i9 < i59) {
                        i59 /= 10;
                        i60--;
                    }
                    int i61 = (i7 + i60) - 1;
                    boolean z9 = i61 < -3 || i61 >= 7;
                    if (z3 && !z) {
                        i9--;
                    }
                    int i62 = 0;
                    while (true) {
                        int i63 = i9 / 10;
                        int i64 = i6 / 10;
                        if (i63 <= i64 || (i9 < 100 && z9)) {
                            break;
                        }
                        z2 &= i6 % 10 == 0;
                        i8 = i4 % 10;
                        i4 /= 10;
                        i62++;
                        i9 = i63;
                        i6 = i64;
                    }
                    if (z2 && z) {
                        while (i6 % 10 == 0 && (i9 >= 100 || !z9)) {
                            i9 /= 10;
                            i8 = i4 % 10;
                            i4 /= 10;
                            i6 /= 10;
                            i62++;
                        }
                    }
                    if (z4 && i8 == 5 && i4 % 2 == 0) {
                        i8 = 4;
                    }
                    int i65 = i4 + (((i4 != i6 || (z2 && z)) && i8 < 5) ? 0 : 1);
                    int i66 = i60 - i62;
                    if (z5) {
                        i10 = i2 + 1;
                        cArr[i2] = '-';
                    } else {
                        i10 = i2;
                    }
                    if (z9) {
                        for (int i67 = 0; i67 < i66 - 1; i67++) {
                            int i68 = i65 % 10;
                            i65 /= 10;
                            cArr[(i10 + i66) - i67] = (char) (i68 + 48);
                        }
                        cArr[i10] = (char) ((i65 % 10) + 48);
                        cArr[i10 + 1] = '.';
                        int i69 = i66 + 1 + i10;
                        if (i66 == 1) {
                            cArr[i69] = '0';
                            i69++;
                        }
                        int i70 = i69 + 1;
                        cArr[i69] = 'E';
                        if (i61 < 0) {
                            cArr[i70] = '-';
                            i61 = -i61;
                            i70++;
                        }
                        if (i61 >= 10) {
                            i12 = 48;
                            cArr[i70] = (char) ((i61 / 10) + 48);
                            i70++;
                        } else {
                            i12 = 48;
                        }
                        i11 = i70 + 1;
                        cArr[i70] = (char) ((i61 % 10) + i12);
                    } else {
                        int i71 = 48;
                        if (i61 < 0) {
                            int i72 = i10 + 1;
                            cArr[i10] = '0';
                            int i73 = i72 + 1;
                            cArr[i72] = '.';
                            int i74 = -1;
                            while (i74 > i61) {
                                cArr[i73] = '0';
                                i74--;
                                i73++;
                            }
                            int i75 = i73;
                            int i76 = 0;
                            while (i76 < i66) {
                                cArr[((i73 + i66) - i76) - 1] = (char) ((i65 % 10) + i71);
                                i65 /= 10;
                                i75++;
                                i76++;
                                i71 = 48;
                            }
                            i11 = i75;
                        } else {
                            int i77 = i61 + 1;
                            if (i77 >= i66) {
                                for (int i78 = 0; i78 < i66; i78++) {
                                    cArr[((i10 + i66) - i78) - 1] = (char) ((i65 % 10) + 48);
                                    i65 /= 10;
                                }
                                int i79 = i10 + i66;
                                while (i66 < i77) {
                                    cArr[i79] = '0';
                                    i66++;
                                    i79++;
                                }
                                int i80 = i79 + 1;
                                cArr[i79] = '.';
                                cArr[i80] = '0';
                                i11 = i80 + 1;
                            } else {
                                int i81 = i10 + 1;
                                for (int i82 = 0; i82 < i66; i82++) {
                                    if ((i66 - i82) - 1 == i61) {
                                        cArr[((i81 + i66) - i82) - 1] = '.';
                                        i81--;
                                    }
                                    cArr[((i81 + i66) - i82) - 1] = (char) ((i65 % 10) + 48);
                                    i65 /= 10;
                                }
                                i11 = i66 + 1 + i10;
                            }
                        }
                    }
                    return i11 - i2;
                }
                int i83 = i2 + 1;
                cArr[i2] = '0';
                int i84 = i83 + 1;
                cArr[i83] = '.';
                i16 = i84 + 1;
                cArr[i84] = '0';
            }
        }
        return i16 - i2;
    }
}
