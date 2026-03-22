package p005b.p199l.p258c;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: b.l.c.x */
/* loaded from: classes2.dex */
public abstract class EnumC2494x {

    /* renamed from: c */
    public static final EnumC2494x f6699c;

    /* renamed from: e */
    public static final EnumC2494x f6700e;

    /* renamed from: f */
    public static final /* synthetic */ EnumC2494x[] f6701f;

    /* renamed from: b.l.c.x$a */
    public enum a extends EnumC2494x {
        public a(String str, int i2) {
            super(str, i2, null);
        }
    }

    static {
        a aVar = new a("DEFAULT", 0);
        f6699c = aVar;
        EnumC2494x enumC2494x = new EnumC2494x("STRING", 1) { // from class: b.l.c.x.b
        };
        f6700e = enumC2494x;
        f6701f = new EnumC2494x[]{aVar, enumC2494x};
    }

    public EnumC2494x(String str, int i2, a aVar) {
    }

    public static EnumC2494x valueOf(String str) {
        return (EnumC2494x) Enum.valueOf(EnumC2494x.class, str);
    }

    public static EnumC2494x[] values() {
        return (EnumC2494x[]) f6701f.clone();
    }
}
