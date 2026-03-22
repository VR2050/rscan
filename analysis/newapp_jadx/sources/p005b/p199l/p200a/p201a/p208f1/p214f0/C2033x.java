package p005b.p199l.p200a.p201a.p208f1.p214f0;

import com.google.android.exoplayer2.Format;
import java.util.List;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.f0.x */
/* loaded from: classes.dex */
public final class C2033x {

    /* renamed from: a */
    public final List<Format> f4118a;

    /* renamed from: b */
    public final InterfaceC2052s[] f4119b;

    public C2033x(List<Format> list) {
        this.f4118a = list;
        this.f4119b = new InterfaceC2052s[list.size()];
    }

    /* renamed from: a */
    public void m1611a(InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        for (int i2 = 0; i2 < this.f4119b.length; i2++) {
            dVar.m1584a();
            InterfaceC2052s mo1625t = interfaceC2042i.mo1625t(dVar.m1586c(), 3);
            Format format = this.f4118a.get(i2);
            String str = format.f9245l;
            C4195m.m4761D("application/cea-608".equals(str) || "application/cea-708".equals(str), "Invalid closed caption mime type provided: " + str);
            String str2 = format.f9237c;
            if (str2 == null) {
                str2 = dVar.m1585b();
            }
            mo1625t.mo1615d(Format.m4032I(str2, str, null, -1, format.f9239f, format.f9233D, format.f9234E, null, Long.MAX_VALUE, format.f9247n));
            this.f4119b[i2] = mo1625t;
        }
    }
}
