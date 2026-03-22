package p505n;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nullable;
import p458k.C4371b0;
import p458k.C4488y;
import p458k.C4489z;

/* renamed from: n.x */
/* loaded from: classes3.dex */
public final class C5029x {

    /* renamed from: a */
    public final Method f12921a;

    /* renamed from: b */
    public final C4489z f12922b;

    /* renamed from: c */
    public final String f12923c;

    /* renamed from: d */
    @Nullable
    public final String f12924d;

    /* renamed from: e */
    @Nullable
    public final C4488y f12925e;

    /* renamed from: f */
    @Nullable
    public final C4371b0 f12926f;

    /* renamed from: g */
    public final boolean f12927g;

    /* renamed from: h */
    public final boolean f12928h;

    /* renamed from: i */
    public final boolean f12929i;

    /* renamed from: j */
    public final AbstractC5026u<?>[] f12930j;

    /* renamed from: k */
    public final boolean f12931k;

    /* renamed from: n.x$a */
    public static final class a {

        /* renamed from: a */
        public static final Pattern f12932a = Pattern.compile("\\{([a-zA-Z][a-zA-Z0-9_-]*)\\}");

        /* renamed from: b */
        public static final Pattern f12933b = Pattern.compile("[a-zA-Z][a-zA-Z0-9_-]*");

        /* renamed from: c */
        public final C5031z f12934c;

        /* renamed from: d */
        public final Method f12935d;

        /* renamed from: e */
        public final Annotation[] f12936e;

        /* renamed from: f */
        public final Annotation[][] f12937f;

        /* renamed from: g */
        public final Type[] f12938g;

        /* renamed from: h */
        public boolean f12939h;

        /* renamed from: i */
        public boolean f12940i;

        /* renamed from: j */
        public boolean f12941j;

        /* renamed from: k */
        public boolean f12942k;

        /* renamed from: l */
        public boolean f12943l;

        /* renamed from: m */
        public boolean f12944m;

        /* renamed from: n */
        public boolean f12945n;

        /* renamed from: o */
        public boolean f12946o;

        /* renamed from: p */
        @Nullable
        public String f12947p;

        /* renamed from: q */
        public boolean f12948q;

        /* renamed from: r */
        public boolean f12949r;

        /* renamed from: s */
        public boolean f12950s;

        /* renamed from: t */
        @Nullable
        public String f12951t;

        /* renamed from: u */
        @Nullable
        public C4488y f12952u;

        /* renamed from: v */
        @Nullable
        public C4371b0 f12953v;

        /* renamed from: w */
        @Nullable
        public Set<String> f12954w;

        /* renamed from: x */
        @Nullable
        public AbstractC5026u<?>[] f12955x;

        /* renamed from: y */
        public boolean f12956y;

        public a(C5031z c5031z, Method method) {
            this.f12934c = c5031z;
            this.f12935d = method;
            this.f12936e = method.getAnnotations();
            this.f12938g = method.getGenericParameterTypes();
            this.f12937f = method.getParameterAnnotations();
        }

        /* renamed from: a */
        public static Class<?> m5681a(Class<?> cls) {
            return Boolean.TYPE == cls ? Boolean.class : Byte.TYPE == cls ? Byte.class : Character.TYPE == cls ? Character.class : Double.TYPE == cls ? Double.class : Float.TYPE == cls ? Float.class : Integer.TYPE == cls ? Integer.class : Long.TYPE == cls ? Long.class : Short.TYPE == cls ? Short.class : cls;
        }

        /* renamed from: b */
        public final void m5682b(String str, String str2, boolean z) {
            String str3 = this.f12947p;
            if (str3 != null) {
                throw C4984d0.m5663j(this.f12935d, "Only one HTTP method is allowed. Found: %s and %s.", str3, str);
            }
            this.f12947p = str;
            this.f12948q = z;
            if (str2.isEmpty()) {
                return;
            }
            int indexOf = str2.indexOf(63);
            if (indexOf != -1 && indexOf < str2.length() - 1) {
                String substring = str2.substring(indexOf + 1);
                if (f12932a.matcher(substring).find()) {
                    throw C4984d0.m5663j(this.f12935d, "URL query string \"%s\" must not have replace block. For dynamic query parameters use @Query.", substring);
                }
            }
            this.f12951t = str2;
            Matcher matcher = f12932a.matcher(str2);
            LinkedHashSet linkedHashSet = new LinkedHashSet();
            while (matcher.find()) {
                linkedHashSet.add(matcher.group(1));
            }
            this.f12954w = linkedHashSet;
        }

        /* renamed from: c */
        public final void m5683c(int i2, Type type) {
            if (C4984d0.m5661h(type)) {
                throw C4984d0.m5665l(this.f12935d, i2, "Parameter type must not include a type variable or wildcard: %s", type);
            }
        }
    }

    public C5029x(a aVar) {
        this.f12921a = aVar.f12935d;
        this.f12922b = aVar.f12934c.f12961c;
        this.f12923c = aVar.f12947p;
        this.f12924d = aVar.f12951t;
        this.f12925e = aVar.f12952u;
        this.f12926f = aVar.f12953v;
        this.f12927g = aVar.f12948q;
        this.f12928h = aVar.f12949r;
        this.f12929i = aVar.f12950s;
        this.f12930j = aVar.f12955x;
        this.f12931k = aVar.f12956y;
    }
}
