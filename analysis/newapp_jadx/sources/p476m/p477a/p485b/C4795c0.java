package p476m.p477a.p485b;

import java.io.Serializable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: m.a.b.c0 */
/* loaded from: classes3.dex */
public class C4795c0 implements Serializable, Cloneable {
    private static final long serialVersionUID = 8950662842175091068L;

    /* renamed from: c */
    public final String f12279c;

    /* renamed from: e */
    public final int f12280e;

    /* renamed from: f */
    public final int f12281f;

    public C4795c0(String str, int i2, int i3) {
        C2354n.m2470e1(str, "Protocol name");
        this.f12279c = str;
        C2354n.m2462c1(i2, "Protocol major version");
        this.f12280e = i2;
        C2354n.m2462c1(i3, "Protocol minor version");
        this.f12281f = i3;
    }

    /* renamed from: a */
    public C4795c0 mo5469a(int i2, int i3) {
        return (i2 == this.f12280e && i3 == this.f12281f) ? this : new C4795c0(this.f12279c, i2, i3);
    }

    /* renamed from: c */
    public final boolean m5470c(C4795c0 c4795c0) {
        if (c4795c0 != null && this.f12279c.equals(c4795c0.f12279c)) {
            C2354n.m2470e1(c4795c0, "Protocol version");
            Object[] objArr = {this, c4795c0};
            if (!this.f12279c.equals(c4795c0.f12279c)) {
                throw new IllegalArgumentException(String.format("Versions for different protocols cannot be compared: %s %s", objArr));
            }
            int i2 = this.f12280e - c4795c0.f12280e;
            if (i2 == 0) {
                i2 = this.f12281f - c4795c0.f12281f;
            }
            if (i2 <= 0) {
                return true;
            }
        }
        return false;
    }

    public Object clone() {
        return super.clone();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4795c0)) {
            return false;
        }
        C4795c0 c4795c0 = (C4795c0) obj;
        return this.f12279c.equals(c4795c0.f12279c) && this.f12280e == c4795c0.f12280e && this.f12281f == c4795c0.f12281f;
    }

    public final int hashCode() {
        return (this.f12279c.hashCode() ^ (this.f12280e * 100000)) ^ this.f12281f;
    }

    public String toString() {
        return this.f12279c + '/' + Integer.toString(this.f12280e) + '.' + Integer.toString(this.f12281f);
    }
}
