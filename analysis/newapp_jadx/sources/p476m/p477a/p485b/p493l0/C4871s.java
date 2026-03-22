package p476m.p477a.p485b.p493l0;

import kotlin.text.Typography;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: m.a.b.l0.s */
/* loaded from: classes3.dex */
public class C4871s {

    /* renamed from: a */
    public final int f12473a;

    /* renamed from: b */
    public int f12474b;

    public C4871s(int i2, int i3) {
        if (i2 < 0) {
            throw new IndexOutOfBoundsException("Lower bound cannot be negative");
        }
        if (i2 > i3) {
            throw new IndexOutOfBoundsException("Lower bound cannot be greater then upper bound");
        }
        this.f12473a = i3;
        this.f12474b = i2;
    }

    /* renamed from: a */
    public boolean m5541a() {
        return this.f12474b >= this.f12473a;
    }

    /* renamed from: b */
    public void m5542b(int i2) {
        if (i2 < 0) {
            throw new IndexOutOfBoundsException(C1499a.m629o("pos: ", i2, " < lowerBound: ", 0));
        }
        if (i2 <= this.f12473a) {
            this.f12474b = i2;
        } else {
            StringBuilder m588J = C1499a.m588J("pos: ", i2, " > upperBound: ");
            m588J.append(this.f12473a);
            throw new IndexOutOfBoundsException(m588J.toString());
        }
    }

    public String toString() {
        StringBuilder m584F = C1499a.m584F('[');
        m584F.append(Integer.toString(0));
        m584F.append(Typography.greater);
        m584F.append(Integer.toString(this.f12474b));
        m584F.append(Typography.greater);
        m584F.append(Integer.toString(this.f12473a));
        m584F.append(']');
        return m584F.toString();
    }
}
