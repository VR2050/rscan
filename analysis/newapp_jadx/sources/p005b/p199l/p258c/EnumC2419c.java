package p005b.p199l.p258c;

import java.lang.reflect.Field;
import java.util.Locale;
import p005b.p131d.p132a.p133a.C1499a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: b.l.c.c */
/* loaded from: classes2.dex */
public abstract class EnumC2419c implements InterfaceC2469d {

    /* renamed from: c */
    public static final EnumC2419c f6445c;

    /* renamed from: e */
    public static final EnumC2419c f6446e;

    /* renamed from: f */
    public static final EnumC2419c f6447f;

    /* renamed from: g */
    public static final EnumC2419c f6448g;

    /* renamed from: h */
    public static final EnumC2419c f6449h;

    /* renamed from: i */
    public static final EnumC2419c f6450i;

    /* renamed from: j */
    public static final /* synthetic */ EnumC2419c[] f6451j;

    /* renamed from: b.l.c.c$a */
    public enum a extends EnumC2419c {
        public a(String str, int i2) {
            super(str, i2, null);
        }

        @Override // p005b.p199l.p258c.InterfaceC2469d
        /* renamed from: a */
        public String mo2756a(Field field) {
            return field.getName();
        }
    }

    static {
        a aVar = new a("IDENTITY", 0);
        f6445c = aVar;
        EnumC2419c enumC2419c = new EnumC2419c("UPPER_CAMEL_CASE", 1) { // from class: b.l.c.c.b
            @Override // p005b.p199l.p258c.InterfaceC2469d
            /* renamed from: a */
            public String mo2756a(Field field) {
                return EnumC2419c.m2755c(field.getName());
            }
        };
        f6446e = enumC2419c;
        EnumC2419c enumC2419c2 = new EnumC2419c("UPPER_CAMEL_CASE_WITH_SPACES", 2) { // from class: b.l.c.c.c
            @Override // p005b.p199l.p258c.InterfaceC2469d
            /* renamed from: a */
            public String mo2756a(Field field) {
                return EnumC2419c.m2755c(EnumC2419c.m2754b(field.getName(), " "));
            }
        };
        f6447f = enumC2419c2;
        EnumC2419c enumC2419c3 = new EnumC2419c("LOWER_CASE_WITH_UNDERSCORES", 3) { // from class: b.l.c.c.d
            @Override // p005b.p199l.p258c.InterfaceC2469d
            /* renamed from: a */
            public String mo2756a(Field field) {
                return EnumC2419c.m2754b(field.getName(), "_").toLowerCase(Locale.ENGLISH);
            }
        };
        f6448g = enumC2419c3;
        EnumC2419c enumC2419c4 = new EnumC2419c("LOWER_CASE_WITH_DASHES", 4) { // from class: b.l.c.c.e
            @Override // p005b.p199l.p258c.InterfaceC2469d
            /* renamed from: a */
            public String mo2756a(Field field) {
                return EnumC2419c.m2754b(field.getName(), "-").toLowerCase(Locale.ENGLISH);
            }
        };
        f6449h = enumC2419c4;
        EnumC2419c enumC2419c5 = new EnumC2419c("LOWER_CASE_WITH_DOTS", 5) { // from class: b.l.c.c.f
            @Override // p005b.p199l.p258c.InterfaceC2469d
            /* renamed from: a */
            public String mo2756a(Field field) {
                return EnumC2419c.m2754b(field.getName(), ".").toLowerCase(Locale.ENGLISH);
            }
        };
        f6450i = enumC2419c5;
        f6451j = new EnumC2419c[]{aVar, enumC2419c, enumC2419c2, enumC2419c3, enumC2419c4, enumC2419c5};
    }

    public EnumC2419c(String str, int i2, a aVar) {
    }

    /* renamed from: b */
    public static String m2754b(String str, String str2) {
        StringBuilder sb = new StringBuilder();
        int length = str.length();
        for (int i2 = 0; i2 < length; i2++) {
            char charAt = str.charAt(i2);
            if (Character.isUpperCase(charAt) && sb.length() != 0) {
                sb.append(str2);
            }
            sb.append(charAt);
        }
        return sb.toString();
    }

    /* renamed from: c */
    public static String m2755c(String str) {
        String valueOf;
        StringBuilder sb = new StringBuilder();
        int i2 = 0;
        char charAt = str.charAt(0);
        int length = str.length();
        while (i2 < length - 1 && !Character.isLetter(charAt)) {
            sb.append(charAt);
            i2++;
            charAt = str.charAt(i2);
        }
        if (Character.isUpperCase(charAt)) {
            return str;
        }
        char upperCase = Character.toUpperCase(charAt);
        int i3 = i2 + 1;
        if (i3 < str.length()) {
            StringBuilder m584F = C1499a.m584F(upperCase);
            m584F.append(str.substring(i3));
            valueOf = m584F.toString();
        } else {
            valueOf = String.valueOf(upperCase);
        }
        sb.append(valueOf);
        return sb.toString();
    }

    public static EnumC2419c valueOf(String str) {
        return (EnumC2419c) Enum.valueOf(EnumC2419c.class, str);
    }

    public static EnumC2419c[] values() {
        return (EnumC2419c[]) f6451j.clone();
    }
}
