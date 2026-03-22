package p005b.p199l.p200a.p201a.p208f1;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.io.EOFException;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.g */
/* loaded from: classes.dex */
public final class C2036g implements InterfaceC2052s {
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
    /* renamed from: a */
    public int mo1612a(C2003e c2003e, int i2, boolean z) {
        int min = Math.min(c2003e.f3792g, i2);
        c2003e.m1570j(min);
        if (min == 0) {
            byte[] bArr = c2003e.f3786a;
            min = c2003e.m1567g(bArr, 0, Math.min(i2, bArr.length), 0, true);
        }
        c2003e.m1562b(min);
        if (min != -1) {
            return min;
        }
        if (z) {
            return -1;
        }
        throw new EOFException();
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
    /* renamed from: b */
    public void mo1613b(C2360t c2360t, int i2) {
        c2360t.m2567C(c2360t.f6134b + i2);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
    /* renamed from: c */
    public void mo1614c(long j2, int i2, int i3, int i4, @Nullable InterfaceC2052s.a aVar) {
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
    /* renamed from: d */
    public void mo1615d(Format format) {
    }
}
