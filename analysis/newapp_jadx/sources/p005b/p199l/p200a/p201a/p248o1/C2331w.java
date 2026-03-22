package p005b.p199l.p200a.p201a.p248o1;

import java.io.FileNotFoundException;
import java.io.IOException;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p248o1.C2281a0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2333y;

/* renamed from: b.l.a.a.o1.w */
/* loaded from: classes.dex */
public class C2331w implements InterfaceC2334z {
    /* renamed from: a */
    public long m2279a(int i2, long j2, IOException iOException, int i3) {
        if (!(iOException instanceof InterfaceC2333y.d)) {
            return -9223372036854775807L;
        }
        int i4 = ((InterfaceC2333y.d) iOException).f6016c;
        return (i4 == 404 || i4 == 410 || i4 == 416) ? 60000L : -9223372036854775807L;
    }

    /* renamed from: b */
    public int m2280b(int i2) {
        return i2 == 7 ? 6 : 3;
    }

    /* renamed from: c */
    public long m2281c(int i2, long j2, IOException iOException, int i3) {
        if ((iOException instanceof C2205l0) || (iOException instanceof FileNotFoundException) || (iOException instanceof C2281a0.h)) {
            return -9223372036854775807L;
        }
        return Math.min((i3 - 1) * 1000, 5000);
    }
}
