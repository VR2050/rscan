package p476m.p477a.p485b.p486h0;

import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: m.a.b.h0.a */
/* loaded from: classes3.dex */
public class C4805a implements Cloneable {

    /* renamed from: c */
    public static final C4805a f12283c = new C4805a(-1, -1);

    /* renamed from: e */
    public final int f12284e;

    /* renamed from: f */
    public final int f12285f;

    public C4805a(int i2, int i3) {
        this.f12284e = i2;
        this.f12285f = i3;
    }

    public Object clone() {
        return (C4805a) super.clone();
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("[maxLineLength=");
        m586H.append(this.f12284e);
        m586H.append(", maxHeaderCount=");
        return C1499a.m580B(m586H, this.f12285f, "]");
    }
}
