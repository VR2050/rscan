package p476m.p477a.p485b;

/* renamed from: m.a.b.v */
/* loaded from: classes3.dex */
public final class C4902v extends C4795c0 {

    /* renamed from: g */
    public static final C4902v f12499g = new C4902v(0, 9);

    /* renamed from: h */
    public static final C4902v f12500h = new C4902v(1, 0);

    /* renamed from: i */
    public static final C4902v f12501i = new C4902v(1, 1);
    private static final long serialVersionUID = -5856653513894415344L;

    public C4902v(int i2, int i3) {
        super("HTTP", i2, i3);
    }

    @Override // p476m.p477a.p485b.C4795c0
    /* renamed from: a */
    public C4795c0 mo5469a(int i2, int i3) {
        if (i2 == this.f12280e && i3 == this.f12281f) {
            return this;
        }
        if (i2 == 1) {
            if (i3 == 0) {
                return f12500h;
            }
            if (i3 == 1) {
                return f12501i;
            }
        }
        return (i2 == 0 && i3 == 9) ? f12499g : new C4902v(i2, i3);
    }
}
