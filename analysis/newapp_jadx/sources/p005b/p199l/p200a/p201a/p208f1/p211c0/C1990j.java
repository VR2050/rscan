package p005b.p199l.p200a.p201a.p208f1.p211c0;

import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.c0.j */
/* loaded from: classes.dex */
public final class C1990j {

    /* renamed from: a */
    public final boolean f3689a;

    /* renamed from: b */
    @Nullable
    public final String f3690b;

    /* renamed from: c */
    public final InterfaceC2052s.a f3691c;

    /* renamed from: d */
    public final int f3692d;

    /* renamed from: e */
    @Nullable
    public final byte[] f3693e;

    public C1990j(boolean z, @Nullable String str, int i2, byte[] bArr, int i3, int i4, @Nullable byte[] bArr2) {
        int i5 = 1;
        C4195m.m4765F((bArr2 == null) ^ (i2 == 0));
        this.f3689a = z;
        this.f3690b = str;
        this.f3692d = i2;
        this.f3693e = bArr2;
        if (str != null && (str.equals("cbc1") || str.equals("cbcs"))) {
            i5 = 2;
        }
        this.f3691c = new InterfaceC2052s.a(i5, bArr, i3, i4);
    }
}
