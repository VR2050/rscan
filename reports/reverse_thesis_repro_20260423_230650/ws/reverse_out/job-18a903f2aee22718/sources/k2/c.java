package k2;

import t2.j;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class c extends b {
    public static int d(int i3, int... iArr) {
        j.f(iArr, "other");
        for (int i4 : iArr) {
            i3 = Math.max(i3, i4);
        }
        return i3;
    }

    public static int e(int i3, int... iArr) {
        j.f(iArr, "other");
        for (int i4 : iArr) {
            i3 = Math.min(i3, i4);
        }
        return i3;
    }
}
