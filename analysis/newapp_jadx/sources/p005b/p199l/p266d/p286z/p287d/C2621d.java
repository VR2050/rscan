package p005b.p199l.p266d.p286z.p287d;

/* renamed from: b.l.d.z.d.d */
/* loaded from: classes2.dex */
public final class C2621d {

    /* renamed from: a */
    public final int f7147a;

    /* renamed from: b */
    public final int f7148b;

    /* renamed from: c */
    public final int f7149c;

    /* renamed from: d */
    public final int f7150d;

    /* renamed from: e */
    public int f7151e = -1;

    public C2621d(int i2, int i3, int i4, int i5) {
        this.f7147a = i2;
        this.f7148b = i3;
        this.f7149c = i4;
        this.f7150d = i5;
    }

    /* renamed from: a */
    public boolean m3065a() {
        int i2 = this.f7151e;
        return i2 != -1 && this.f7149c == (i2 % 3) * 3;
    }

    /* renamed from: b */
    public void m3066b() {
        this.f7151e = (this.f7149c / 3) + ((this.f7150d / 30) * 3);
    }

    public String toString() {
        return this.f7151e + "|" + this.f7150d;
    }
}
