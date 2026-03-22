package p005b.p199l.p266d.p267a0.p268c;

import p005b.p199l.p266d.p274v.C2544b;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: b.l.d.a0.c.c */
/* loaded from: classes2.dex */
public abstract class EnumC2502c {

    /* renamed from: c */
    public static final EnumC2502c f6729c;

    /* renamed from: e */
    public static final EnumC2502c f6730e;

    /* renamed from: f */
    public static final EnumC2502c f6731f;

    /* renamed from: g */
    public static final EnumC2502c f6732g;

    /* renamed from: h */
    public static final EnumC2502c f6733h;

    /* renamed from: i */
    public static final EnumC2502c f6734i;

    /* renamed from: j */
    public static final EnumC2502c f6735j;

    /* renamed from: k */
    public static final EnumC2502c f6736k;

    /* renamed from: l */
    public static final /* synthetic */ EnumC2502c[] f6737l;

    /* renamed from: b.l.d.a0.c.c$a */
    public enum a extends EnumC2502c {
        public a(String str, int i2) {
            super(str, i2, null);
        }

        @Override // p005b.p199l.p266d.p267a0.p268c.EnumC2502c
        /* renamed from: a */
        public boolean mo2874a(int i2, int i3) {
            return ((i2 + i3) & 1) == 0;
        }
    }

    static {
        a aVar = new a("DATA_MASK_000", 0);
        f6729c = aVar;
        EnumC2502c enumC2502c = new EnumC2502c("DATA_MASK_001", 1) { // from class: b.l.d.a0.c.c.b
            @Override // p005b.p199l.p266d.p267a0.p268c.EnumC2502c
            /* renamed from: a */
            public boolean mo2874a(int i2, int i3) {
                return (i2 & 1) == 0;
            }
        };
        f6730e = enumC2502c;
        EnumC2502c enumC2502c2 = new EnumC2502c("DATA_MASK_010", 2) { // from class: b.l.d.a0.c.c.c
            @Override // p005b.p199l.p266d.p267a0.p268c.EnumC2502c
            /* renamed from: a */
            public boolean mo2874a(int i2, int i3) {
                return i3 % 3 == 0;
            }
        };
        f6731f = enumC2502c2;
        EnumC2502c enumC2502c3 = new EnumC2502c("DATA_MASK_011", 3) { // from class: b.l.d.a0.c.c.d
            @Override // p005b.p199l.p266d.p267a0.p268c.EnumC2502c
            /* renamed from: a */
            public boolean mo2874a(int i2, int i3) {
                return (i2 + i3) % 3 == 0;
            }
        };
        f6732g = enumC2502c3;
        EnumC2502c enumC2502c4 = new EnumC2502c("DATA_MASK_100", 4) { // from class: b.l.d.a0.c.c.e
            @Override // p005b.p199l.p266d.p267a0.p268c.EnumC2502c
            /* renamed from: a */
            public boolean mo2874a(int i2, int i3) {
                return (((i3 / 3) + (i2 / 2)) & 1) == 0;
            }
        };
        f6733h = enumC2502c4;
        EnumC2502c enumC2502c5 = new EnumC2502c("DATA_MASK_101", 5) { // from class: b.l.d.a0.c.c.f
            @Override // p005b.p199l.p266d.p267a0.p268c.EnumC2502c
            /* renamed from: a */
            public boolean mo2874a(int i2, int i3) {
                return (i2 * i3) % 6 == 0;
            }
        };
        f6734i = enumC2502c5;
        EnumC2502c enumC2502c6 = new EnumC2502c("DATA_MASK_110", 6) { // from class: b.l.d.a0.c.c.g
            @Override // p005b.p199l.p266d.p267a0.p268c.EnumC2502c
            /* renamed from: a */
            public boolean mo2874a(int i2, int i3) {
                return (i2 * i3) % 6 < 3;
            }
        };
        f6735j = enumC2502c6;
        EnumC2502c enumC2502c7 = new EnumC2502c("DATA_MASK_111", 7) { // from class: b.l.d.a0.c.c.h
            @Override // p005b.p199l.p266d.p267a0.p268c.EnumC2502c
            /* renamed from: a */
            public boolean mo2874a(int i2, int i3) {
                return ((((i2 * i3) % 3) + (i2 + i3)) & 1) == 0;
            }
        };
        f6736k = enumC2502c7;
        f6737l = new EnumC2502c[]{aVar, enumC2502c, enumC2502c2, enumC2502c3, enumC2502c4, enumC2502c5, enumC2502c6, enumC2502c7};
    }

    public EnumC2502c(String str, int i2, a aVar) {
    }

    public static EnumC2502c valueOf(String str) {
        return (EnumC2502c) Enum.valueOf(EnumC2502c.class, str);
    }

    public static EnumC2502c[] values() {
        return (EnumC2502c[]) f6737l.clone();
    }

    /* renamed from: a */
    public abstract boolean mo2874a(int i2, int i3);

    /* renamed from: b */
    public final void m2875b(C2544b c2544b, int i2) {
        for (int i3 = 0; i3 < i2; i3++) {
            for (int i4 = 0; i4 < i2; i4++) {
                if (mo2874a(i3, i4)) {
                    c2544b.m2957a(i4, i3);
                }
            }
        }
    }
}
