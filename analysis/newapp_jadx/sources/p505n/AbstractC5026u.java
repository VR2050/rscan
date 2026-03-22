package p505n;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;
import kotlin.jvm.internal.Intrinsics;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.AbstractC4387j0;
import p458k.C4373c0;
import p458k.C4488y;

/* renamed from: n.u */
/* loaded from: classes3.dex */
public abstract class AbstractC5026u<T> {

    /* renamed from: n.u$a */
    public static final class a<T> extends AbstractC5026u<T> {

        /* renamed from: a */
        public final Method f12859a;

        /* renamed from: b */
        public final int f12860b;

        /* renamed from: c */
        public final InterfaceC5013h<T, AbstractC4387j0> f12861c;

        public a(Method method, int i2, InterfaceC5013h<T, AbstractC4387j0> interfaceC5013h) {
            this.f12859a = method;
            this.f12860b = i2;
            this.f12861c = interfaceC5013h;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable T t) {
            if (t == null) {
                throw C4984d0.m5665l(this.f12859a, this.f12860b, "Body parameter value must not be null.", new Object[0]);
            }
            try {
                c5028w.f12918m = this.f12861c.convert(t);
            } catch (IOException e2) {
                throw C4984d0.m5666m(this.f12859a, e2, this.f12860b, "Unable to convert " + t + " to RequestBody", new Object[0]);
            }
        }
    }

    /* renamed from: n.u$b */
    public static final class b<T> extends AbstractC5026u<T> {

        /* renamed from: a */
        public final String f12862a;

        /* renamed from: b */
        public final InterfaceC5013h<T, String> f12863b;

        /* renamed from: c */
        public final boolean f12864c;

        public b(String str, InterfaceC5013h<T, String> interfaceC5013h, boolean z) {
            Objects.requireNonNull(str, "name == null");
            this.f12862a = str;
            this.f12863b = interfaceC5013h;
            this.f12864c = z;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable T t) {
            String convert;
            if (t == null || (convert = this.f12863b.convert(t)) == null) {
                return;
            }
            c5028w.m5677a(this.f12862a, convert, this.f12864c);
        }
    }

    /* renamed from: n.u$c */
    public static final class c<T> extends AbstractC5026u<Map<String, T>> {

        /* renamed from: a */
        public final Method f12865a;

        /* renamed from: b */
        public final int f12866b;

        /* renamed from: c */
        public final InterfaceC5013h<T, String> f12867c;

        /* renamed from: d */
        public final boolean f12868d;

        public c(Method method, int i2, InterfaceC5013h<T, String> interfaceC5013h, boolean z) {
            this.f12865a = method;
            this.f12866b = i2;
            this.f12867c = interfaceC5013h;
            this.f12868d = z;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable Object obj) {
            Map map = (Map) obj;
            if (map == null) {
                throw C4984d0.m5665l(this.f12865a, this.f12866b, "Field map was null.", new Object[0]);
            }
            for (Map.Entry entry : map.entrySet()) {
                String str = (String) entry.getKey();
                if (str == null) {
                    throw C4984d0.m5665l(this.f12865a, this.f12866b, "Field map contained null key.", new Object[0]);
                }
                Object value = entry.getValue();
                if (value == null) {
                    throw C4984d0.m5665l(this.f12865a, this.f12866b, C1499a.m639y("Field map contained null value for key '", str, "'."), new Object[0]);
                }
                String str2 = (String) this.f12867c.convert(value);
                if (str2 == null) {
                    throw C4984d0.m5665l(this.f12865a, this.f12866b, "Field map value '" + value + "' converted to null by " + this.f12867c.getClass().getName() + " for key '" + str + "'.", new Object[0]);
                }
                c5028w.m5677a(str, str2, this.f12868d);
            }
        }
    }

    /* renamed from: n.u$d */
    public static final class d<T> extends AbstractC5026u<T> {

        /* renamed from: a */
        public final String f12869a;

        /* renamed from: b */
        public final InterfaceC5013h<T, String> f12870b;

        public d(String str, InterfaceC5013h<T, String> interfaceC5013h) {
            Objects.requireNonNull(str, "name == null");
            this.f12869a = str;
            this.f12870b = interfaceC5013h;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable T t) {
            String convert;
            if (t == null || (convert = this.f12870b.convert(t)) == null) {
                return;
            }
            c5028w.m5678b(this.f12869a, convert);
        }
    }

    /* renamed from: n.u$e */
    public static final class e<T> extends AbstractC5026u<Map<String, T>> {

        /* renamed from: a */
        public final Method f12871a;

        /* renamed from: b */
        public final int f12872b;

        /* renamed from: c */
        public final InterfaceC5013h<T, String> f12873c;

        public e(Method method, int i2, InterfaceC5013h<T, String> interfaceC5013h) {
            this.f12871a = method;
            this.f12872b = i2;
            this.f12873c = interfaceC5013h;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable Object obj) {
            Map map = (Map) obj;
            if (map == null) {
                throw C4984d0.m5665l(this.f12871a, this.f12872b, "Header map was null.", new Object[0]);
            }
            for (Map.Entry entry : map.entrySet()) {
                String str = (String) entry.getKey();
                if (str == null) {
                    throw C4984d0.m5665l(this.f12871a, this.f12872b, "Header map contained null key.", new Object[0]);
                }
                Object value = entry.getValue();
                if (value == null) {
                    throw C4984d0.m5665l(this.f12871a, this.f12872b, C1499a.m639y("Header map contained null value for key '", str, "'."), new Object[0]);
                }
                c5028w.m5678b(str, (String) this.f12873c.convert(value));
            }
        }
    }

    /* renamed from: n.u$f */
    public static final class f extends AbstractC5026u<C4488y> {

        /* renamed from: a */
        public final Method f12874a;

        /* renamed from: b */
        public final int f12875b;

        public f(Method method, int i2) {
            this.f12874a = method;
            this.f12875b = i2;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable C4488y c4488y) {
            C4488y headers = c4488y;
            if (headers == null) {
                throw C4984d0.m5665l(this.f12874a, this.f12875b, "Headers parameter must not be null.", new Object[0]);
            }
            C4488y.a aVar = c5028w.f12913h;
            Objects.requireNonNull(aVar);
            Intrinsics.checkParameterIsNotNull(headers, "headers");
            int size = headers.size();
            for (int i2 = 0; i2 < size; i2++) {
                aVar.m5284c(headers.m5278b(i2), headers.m5280d(i2));
            }
        }
    }

    /* renamed from: n.u$g */
    public static final class g<T> extends AbstractC5026u<T> {

        /* renamed from: a */
        public final Method f12876a;

        /* renamed from: b */
        public final int f12877b;

        /* renamed from: c */
        public final C4488y f12878c;

        /* renamed from: d */
        public final InterfaceC5013h<T, AbstractC4387j0> f12879d;

        public g(Method method, int i2, C4488y c4488y, InterfaceC5013h<T, AbstractC4387j0> interfaceC5013h) {
            this.f12876a = method;
            this.f12877b = i2;
            this.f12878c = c4488y;
            this.f12879d = interfaceC5013h;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable T t) {
            if (t == null) {
                return;
            }
            try {
                c5028w.m5679c(this.f12878c, this.f12879d.convert(t));
            } catch (IOException e2) {
                throw C4984d0.m5665l(this.f12876a, this.f12877b, "Unable to convert " + t + " to RequestBody", e2);
            }
        }
    }

    /* renamed from: n.u$h */
    public static final class h<T> extends AbstractC5026u<Map<String, T>> {

        /* renamed from: a */
        public final Method f12880a;

        /* renamed from: b */
        public final int f12881b;

        /* renamed from: c */
        public final InterfaceC5013h<T, AbstractC4387j0> f12882c;

        /* renamed from: d */
        public final String f12883d;

        public h(Method method, int i2, InterfaceC5013h<T, AbstractC4387j0> interfaceC5013h, String str) {
            this.f12880a = method;
            this.f12881b = i2;
            this.f12882c = interfaceC5013h;
            this.f12883d = str;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable Object obj) {
            Map map = (Map) obj;
            if (map == null) {
                throw C4984d0.m5665l(this.f12880a, this.f12881b, "Part map was null.", new Object[0]);
            }
            for (Map.Entry entry : map.entrySet()) {
                String str = (String) entry.getKey();
                if (str == null) {
                    throw C4984d0.m5665l(this.f12880a, this.f12881b, "Part map contained null key.", new Object[0]);
                }
                Object value = entry.getValue();
                if (value == null) {
                    throw C4984d0.m5665l(this.f12880a, this.f12881b, C1499a.m639y("Part map contained null value for key '", str, "'."), new Object[0]);
                }
                c5028w.m5679c(C4488y.f12040c.m5290c("Content-Disposition", C1499a.m639y("form-data; name=\"", str, "\""), "Content-Transfer-Encoding", this.f12883d), (AbstractC4387j0) this.f12882c.convert(value));
            }
        }
    }

    /* renamed from: n.u$i */
    public static final class i<T> extends AbstractC5026u<T> {

        /* renamed from: a */
        public final Method f12884a;

        /* renamed from: b */
        public final int f12885b;

        /* renamed from: c */
        public final String f12886c;

        /* renamed from: d */
        public final InterfaceC5013h<T, String> f12887d;

        /* renamed from: e */
        public final boolean f12888e;

        public i(Method method, int i2, String str, InterfaceC5013h<T, String> interfaceC5013h, boolean z) {
            this.f12884a = method;
            this.f12885b = i2;
            Objects.requireNonNull(str, "name == null");
            this.f12886c = str;
            this.f12887d = interfaceC5013h;
            this.f12888e = z;
        }

        /* JADX WARN: Removed duplicated region for block: B:54:0x00e5  */
        /* JADX WARN: Removed duplicated region for block: B:57:0x00e8  */
        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void mo5674a(p505n.C5028w r18, @javax.annotation.Nullable T r19) {
            /*
                Method dump skipped, instructions count: 275
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p505n.AbstractC5026u.i.mo5674a(n.w, java.lang.Object):void");
        }
    }

    /* renamed from: n.u$j */
    public static final class j<T> extends AbstractC5026u<T> {

        /* renamed from: a */
        public final String f12889a;

        /* renamed from: b */
        public final InterfaceC5013h<T, String> f12890b;

        /* renamed from: c */
        public final boolean f12891c;

        public j(String str, InterfaceC5013h<T, String> interfaceC5013h, boolean z) {
            Objects.requireNonNull(str, "name == null");
            this.f12889a = str;
            this.f12890b = interfaceC5013h;
            this.f12891c = z;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable T t) {
            String convert;
            if (t == null || (convert = this.f12890b.convert(t)) == null) {
                return;
            }
            c5028w.m5680d(this.f12889a, convert, this.f12891c);
        }
    }

    /* renamed from: n.u$k */
    public static final class k<T> extends AbstractC5026u<Map<String, T>> {

        /* renamed from: a */
        public final Method f12892a;

        /* renamed from: b */
        public final int f12893b;

        /* renamed from: c */
        public final InterfaceC5013h<T, String> f12894c;

        /* renamed from: d */
        public final boolean f12895d;

        public k(Method method, int i2, InterfaceC5013h<T, String> interfaceC5013h, boolean z) {
            this.f12892a = method;
            this.f12893b = i2;
            this.f12894c = interfaceC5013h;
            this.f12895d = z;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable Object obj) {
            Map map = (Map) obj;
            if (map == null) {
                throw C4984d0.m5665l(this.f12892a, this.f12893b, "Query map was null", new Object[0]);
            }
            for (Map.Entry entry : map.entrySet()) {
                String str = (String) entry.getKey();
                if (str == null) {
                    throw C4984d0.m5665l(this.f12892a, this.f12893b, "Query map contained null key.", new Object[0]);
                }
                Object value = entry.getValue();
                if (value == null) {
                    throw C4984d0.m5665l(this.f12892a, this.f12893b, C1499a.m639y("Query map contained null value for key '", str, "'."), new Object[0]);
                }
                String str2 = (String) this.f12894c.convert(value);
                if (str2 == null) {
                    throw C4984d0.m5665l(this.f12892a, this.f12893b, "Query map value '" + value + "' converted to null by " + this.f12894c.getClass().getName() + " for key '" + str + "'.", new Object[0]);
                }
                c5028w.m5680d(str, str2, this.f12895d);
            }
        }
    }

    /* renamed from: n.u$l */
    public static final class l<T> extends AbstractC5026u<T> {

        /* renamed from: a */
        public final InterfaceC5013h<T, String> f12896a;

        /* renamed from: b */
        public final boolean f12897b;

        public l(InterfaceC5013h<T, String> interfaceC5013h, boolean z) {
            this.f12896a = interfaceC5013h;
            this.f12897b = z;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable T t) {
            if (t == null) {
                return;
            }
            c5028w.m5680d(this.f12896a.convert(t), null, this.f12897b);
        }
    }

    /* renamed from: n.u$m */
    public static final class m extends AbstractC5026u<C4373c0.b> {

        /* renamed from: a */
        public static final m f12898a = new m();

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable C4373c0.b bVar) {
            C4373c0.b part = bVar;
            if (part != null) {
                C4373c0.a aVar = c5028w.f12916k;
                Objects.requireNonNull(aVar);
                Intrinsics.checkParameterIsNotNull(part, "part");
                aVar.f11326c.add(part);
            }
        }
    }

    /* renamed from: n.u$n */
    public static final class n extends AbstractC5026u<Object> {

        /* renamed from: a */
        public final Method f12899a;

        /* renamed from: b */
        public final int f12900b;

        public n(Method method, int i2) {
            this.f12899a = method;
            this.f12900b = i2;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable Object obj) {
            if (obj == null) {
                throw C4984d0.m5665l(this.f12899a, this.f12900b, "@Url parameter is null.", new Object[0]);
            }
            Objects.requireNonNull(c5028w);
            c5028w.f12910e = obj.toString();
        }
    }

    /* renamed from: n.u$o */
    public static final class o<T> extends AbstractC5026u<T> {

        /* renamed from: a */
        public final Class<T> f12901a;

        public o(Class<T> cls) {
            this.f12901a = cls;
        }

        @Override // p505n.AbstractC5026u
        /* renamed from: a */
        public void mo5674a(C5028w c5028w, @Nullable T t) {
            c5028w.f12912g.m4977g(this.f12901a, t);
        }
    }

    /* renamed from: a */
    public abstract void mo5674a(C5028w c5028w, @Nullable T t);
}
