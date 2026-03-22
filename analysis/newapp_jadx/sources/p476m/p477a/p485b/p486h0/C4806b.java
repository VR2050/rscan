package p476m.p477a.p485b.p486h0;

import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: m.a.b.h0.b */
/* loaded from: classes3.dex */
public class C4806b implements Cloneable {

    /* renamed from: c */
    public static final C4806b f12286c = new C4806b(0, false, -1, false, true, 0, 0, 0);

    /* renamed from: e */
    public final int f12287e;

    /* renamed from: f */
    public final boolean f12288f;

    /* renamed from: g */
    public final int f12289g;

    /* renamed from: h */
    public final boolean f12290h;

    /* renamed from: i */
    public final boolean f12291i;

    /* renamed from: j */
    public final int f12292j;

    /* renamed from: k */
    public final int f12293k;

    /* renamed from: l */
    public final int f12294l;

    public C4806b(int i2, boolean z, int i3, boolean z2, boolean z3, int i4, int i5, int i6) {
        this.f12287e = i2;
        this.f12288f = z;
        this.f12289g = i3;
        this.f12290h = z2;
        this.f12291i = z3;
        this.f12292j = i4;
        this.f12293k = i5;
        this.f12294l = i6;
    }

    public Object clone() {
        return (C4806b) super.clone();
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("[soTimeout=");
        m586H.append(this.f12287e);
        m586H.append(", soReuseAddress=");
        m586H.append(this.f12288f);
        m586H.append(", soLinger=");
        m586H.append(this.f12289g);
        m586H.append(", soKeepAlive=");
        m586H.append(this.f12290h);
        m586H.append(", tcpNoDelay=");
        m586H.append(this.f12291i);
        m586H.append(", sndBufSize=");
        m586H.append(this.f12292j);
        m586H.append(", rcvBufSize=");
        m586H.append(this.f12293k);
        m586H.append(", backlogSize=");
        return C1499a.m580B(m586H, this.f12294l, "]");
    }
}
