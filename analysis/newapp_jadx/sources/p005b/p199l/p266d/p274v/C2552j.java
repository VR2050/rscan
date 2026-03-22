package p005b.p199l.p266d.p274v;

/* renamed from: b.l.d.v.j */
/* loaded from: classes2.dex */
public final class C2552j {

    /* renamed from: a */
    public final float f6947a;

    /* renamed from: b */
    public final float f6948b;

    /* renamed from: c */
    public final float f6949c;

    /* renamed from: d */
    public final float f6950d;

    /* renamed from: e */
    public final float f6951e;

    /* renamed from: f */
    public final float f6952f;

    /* renamed from: g */
    public final float f6953g;

    /* renamed from: h */
    public final float f6954h;

    /* renamed from: i */
    public final float f6955i;

    public C2552j(float f2, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10) {
        this.f6947a = f2;
        this.f6948b = f5;
        this.f6949c = f8;
        this.f6950d = f3;
        this.f6951e = f6;
        this.f6952f = f9;
        this.f6953g = f4;
        this.f6954h = f7;
        this.f6955i = f10;
    }

    /* renamed from: a */
    public static C2552j m2970a(float f2, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10, float f11, float f12, float f13, float f14, float f15, float f16, float f17) {
        C2552j m2971b = m2971b(f2, f3, f4, f5, f6, f7, f8, f9);
        float f18 = m2971b.f6951e;
        float f19 = m2971b.f6955i;
        float f20 = m2971b.f6952f;
        float f21 = m2971b.f6954h;
        float f22 = (f18 * f19) - (f20 * f21);
        float f23 = m2971b.f6953g;
        float f24 = m2971b.f6950d;
        float f25 = (f20 * f23) - (f24 * f19);
        float f26 = (f24 * f21) - (f18 * f23);
        float f27 = m2971b.f6949c;
        float f28 = m2971b.f6948b;
        float f29 = (f27 * f21) - (f28 * f19);
        float f30 = m2971b.f6947a;
        float f31 = (f19 * f30) - (f27 * f23);
        float f32 = (f23 * f28) - (f21 * f30);
        float f33 = (f28 * f20) - (f27 * f18);
        float f34 = (f27 * f24) - (f20 * f30);
        float f35 = (f30 * f18) - (f28 * f24);
        C2552j m2971b2 = m2971b(f10, f11, f12, f13, f14, f15, f16, f17);
        float f36 = m2971b2.f6947a;
        float f37 = m2971b2.f6950d;
        float f38 = m2971b2.f6953g;
        float f39 = (f37 * f29) + (f36 * f22) + (f38 * f33);
        float f40 = (f38 * f34) + (f37 * f31) + (f36 * f25);
        float f41 = f38 * f35;
        float f42 = f41 + (f37 * f32) + (f36 * f26);
        float f43 = m2971b2.f6948b;
        float f44 = m2971b2.f6951e;
        float f45 = m2971b2.f6954h;
        float f46 = (f45 * f33) + (f44 * f29) + (f43 * f22);
        float f47 = (f45 * f34) + (f44 * f31) + (f43 * f25);
        float f48 = (f44 * f32) + (f43 * f26) + (f45 * f35);
        float f49 = m2971b2.f6949c;
        float f50 = m2971b2.f6952f;
        float f51 = f29 * f50;
        float f52 = m2971b2.f6955i;
        return new C2552j(f39, f40, f42, f46, f47, f48, (f33 * f52) + f51 + (f22 * f49), (f31 * f50) + (f25 * f49) + (f34 * f52), (f52 * f35) + (f50 * f32) + (f49 * f26));
    }

    /* renamed from: b */
    public static C2552j m2971b(float f2, float f3, float f4, float f5, float f6, float f7, float f8, float f9) {
        float f10 = ((f2 - f4) + f6) - f8;
        float f11 = ((f3 - f5) + f7) - f9;
        if (f10 == 0.0f && f11 == 0.0f) {
            return new C2552j(f4 - f2, f6 - f4, f2, f5 - f3, f7 - f5, f3, 0.0f, 0.0f, 1.0f);
        }
        float f12 = f4 - f6;
        float f13 = f8 - f6;
        float f14 = f5 - f7;
        float f15 = f9 - f7;
        float f16 = (f12 * f15) - (f13 * f14);
        float f17 = ((f15 * f10) - (f13 * f11)) / f16;
        float f18 = ((f12 * f11) - (f10 * f14)) / f16;
        return new C2552j((f17 * f4) + (f4 - f2), (f18 * f8) + (f8 - f2), f2, (f17 * f5) + (f5 - f3), (f18 * f9) + (f9 - f3), f3, f17, f18, 1.0f);
    }
}
