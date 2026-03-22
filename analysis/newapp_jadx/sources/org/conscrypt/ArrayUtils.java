package org.conscrypt;

import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes3.dex */
public final class ArrayUtils {
    private ArrayUtils() {
    }

    public static void checkOffsetAndCount(int i2, int i3, int i4) {
        if ((i3 | i4) < 0 || i3 > i2 || i2 - i3 < i4) {
            StringBuilder m589K = C1499a.m589K("length=", i2, "; regionStart=", i3, "; regionLength=");
            m589K.append(i4);
            throw new ArrayIndexOutOfBoundsException(m589K.toString());
        }
    }
}
