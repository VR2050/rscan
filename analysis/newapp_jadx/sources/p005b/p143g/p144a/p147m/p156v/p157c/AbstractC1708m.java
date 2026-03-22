package p005b.p143g.p144a.p147m.p156v.p157c;

import p005b.p143g.p144a.p147m.C1581m;

/* renamed from: b.g.a.m.v.c.m */
/* loaded from: classes.dex */
public abstract class AbstractC1708m {

    /* renamed from: a */
    public static final AbstractC1708m f2499a = new c();

    /* renamed from: b */
    public static final AbstractC1708m f2500b = new a();

    /* renamed from: c */
    public static final AbstractC1708m f2501c;

    /* renamed from: d */
    public static final AbstractC1708m f2502d;

    /* renamed from: e */
    public static final AbstractC1708m f2503e;

    /* renamed from: f */
    public static final C1581m<AbstractC1708m> f2504f;

    /* renamed from: g */
    public static final boolean f2505g;

    /* renamed from: b.g.a.m.v.c.m$a */
    public static class a extends AbstractC1708m {
        @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m
        /* renamed from: a */
        public int mo1003a(int i2, int i3, int i4, int i5) {
            return (mo1004b(i2, i3, i4, i5) == 1.0f || AbstractC1708m.f2505g) ? 2 : 1;
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m
        /* renamed from: b */
        public float mo1004b(int i2, int i3, int i4, int i5) {
            return Math.min(1.0f, AbstractC1708m.f2499a.mo1004b(i2, i3, i4, i5));
        }
    }

    /* renamed from: b.g.a.m.v.c.m$b */
    public static class b extends AbstractC1708m {
        @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m
        /* renamed from: a */
        public int mo1003a(int i2, int i3, int i4, int i5) {
            return 2;
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m
        /* renamed from: b */
        public float mo1004b(int i2, int i3, int i4, int i5) {
            return Math.max(i4 / i2, i5 / i3);
        }
    }

    /* renamed from: b.g.a.m.v.c.m$c */
    public static class c extends AbstractC1708m {
        @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m
        /* renamed from: a */
        public int mo1003a(int i2, int i3, int i4, int i5) {
            return AbstractC1708m.f2505g ? 2 : 1;
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m
        /* renamed from: b */
        public float mo1004b(int i2, int i3, int i4, int i5) {
            if (AbstractC1708m.f2505g) {
                return Math.min(i4 / i2, i5 / i3);
            }
            if (Math.max(i3 / i5, i2 / i4) == 0) {
                return 1.0f;
            }
            return 1.0f / Integer.highestOneBit(r2);
        }
    }

    /* renamed from: b.g.a.m.v.c.m$d */
    public static class d extends AbstractC1708m {
        @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m
        /* renamed from: a */
        public int mo1003a(int i2, int i3, int i4, int i5) {
            return 2;
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m
        /* renamed from: b */
        public float mo1004b(int i2, int i3, int i4, int i5) {
            return 1.0f;
        }
    }

    static {
        b bVar = new b();
        f2501c = bVar;
        f2502d = new d();
        f2503e = bVar;
        f2504f = C1581m.m825a("com.bumptech.glide.load.resource.bitmap.Downsampler.DownsampleStrategy", bVar);
        f2505g = true;
    }

    /* renamed from: a */
    public abstract int mo1003a(int i2, int i3, int i4, int i5);

    /* renamed from: b */
    public abstract float mo1004b(int i2, int i3, int i4, int i5);
}
