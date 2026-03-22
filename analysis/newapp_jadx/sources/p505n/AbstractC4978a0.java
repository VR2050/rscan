package p505n;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.WildcardType;
import java.net.URI;
import java.util.Map;
import javax.annotation.Nullable;
import kotlin.coroutines.Continuation;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.AbstractC4387j0;
import p458k.AbstractC4393m0;
import p458k.C4371b0;
import p458k.C4373c0;
import p458k.C4389k0;
import p458k.C4488y;
import p458k.C4489z;
import p458k.InterfaceC4378f;
import p505n.AbstractC5016k;
import p505n.AbstractC5026u;
import p505n.C4984d0;
import p505n.C5029x;
import p505n.p506e0.InterfaceC4986a;
import p505n.p506e0.InterfaceC4987b;
import p505n.p506e0.InterfaceC4988c;
import p505n.p506e0.InterfaceC4989d;
import p505n.p506e0.InterfaceC4990e;
import p505n.p506e0.InterfaceC4991f;
import p505n.p506e0.InterfaceC4992g;
import p505n.p506e0.InterfaceC4993h;
import p505n.p506e0.InterfaceC4994i;
import p505n.p506e0.InterfaceC4995j;
import p505n.p506e0.InterfaceC4996k;
import p505n.p506e0.InterfaceC4997l;
import p505n.p506e0.InterfaceC4998m;
import p505n.p506e0.InterfaceC4999n;
import p505n.p506e0.InterfaceC5000o;
import p505n.p506e0.InterfaceC5001p;
import p505n.p506e0.InterfaceC5002q;
import p505n.p506e0.InterfaceC5003r;
import p505n.p506e0.InterfaceC5004s;
import p505n.p506e0.InterfaceC5005t;
import p505n.p506e0.InterfaceC5006u;
import p505n.p506e0.InterfaceC5007v;
import p505n.p506e0.InterfaceC5009x;
import p505n.p506e0.InterfaceC5010y;

/* renamed from: n.a0 */
/* loaded from: classes3.dex */
public abstract class AbstractC4978a0<T> {
    /* renamed from: b */
    public static <T> AbstractC4978a0<T> m5648b(C5031z c5031z, Method method) {
        Type genericReturnType;
        boolean z;
        int i2;
        int i3;
        AbstractC5026u<?> abstractC5026u;
        int i4;
        int i5;
        int i6;
        int i7;
        AbstractC5026u<?> abstractC5026u2;
        AbstractC5026u<?> gVar;
        AbstractC5026u<?> c5025t;
        AbstractC5026u<?> cVar;
        AbstractC5026u<?> bVar;
        C5029x.a aVar = new C5029x.a(c5031z, method);
        for (Annotation annotation : aVar.f12936e) {
            if (annotation instanceof InterfaceC4987b) {
                aVar.m5682b("DELETE", ((InterfaceC4987b) annotation).value(), false);
            } else if (annotation instanceof InterfaceC4991f) {
                aVar.m5682b("GET", ((InterfaceC4991f) annotation).value(), false);
            } else if (annotation instanceof InterfaceC4992g) {
                aVar.m5682b("HEAD", ((InterfaceC4992g) annotation).value(), false);
            } else if (annotation instanceof InterfaceC4999n) {
                aVar.m5682b("PATCH", ((InterfaceC4999n) annotation).value(), true);
            } else if (annotation instanceof InterfaceC5000o) {
                aVar.m5682b("POST", ((InterfaceC5000o) annotation).value(), true);
            } else if (annotation instanceof InterfaceC5001p) {
                aVar.m5682b("PUT", ((InterfaceC5001p) annotation).value(), true);
            } else if (annotation instanceof InterfaceC4998m) {
                aVar.m5682b("OPTIONS", ((InterfaceC4998m) annotation).value(), false);
            } else if (annotation instanceof InterfaceC4993h) {
                InterfaceC4993h interfaceC4993h = (InterfaceC4993h) annotation;
                aVar.m5682b(interfaceC4993h.method(), interfaceC4993h.path(), interfaceC4993h.hasBody());
            } else if (annotation instanceof InterfaceC4996k) {
                String[] value = ((InterfaceC4996k) annotation).value();
                if (value.length == 0) {
                    throw C4984d0.m5663j(aVar.f12935d, "@Headers annotation is empty.", new Object[0]);
                }
                C4488y.a aVar2 = new C4488y.a();
                for (String str : value) {
                    int indexOf = str.indexOf(58);
                    if (indexOf == -1 || indexOf == 0 || indexOf == str.length() - 1) {
                        throw C4984d0.m5663j(aVar.f12935d, "@Headers value must be in the form \"Name: Value\". Found: \"%s\"", str);
                    }
                    String substring = str.substring(0, indexOf);
                    String trim = str.substring(indexOf + 1).trim();
                    if ("Content-Type".equalsIgnoreCase(substring)) {
                        try {
                            C4371b0.a aVar3 = C4371b0.f11309c;
                            aVar.f12953v = C4371b0.a.m4945a(trim);
                        } catch (IllegalArgumentException e2) {
                            throw C4984d0.m5664k(aVar.f12935d, e2, "Malformed content type: %s", trim);
                        }
                    } else {
                        aVar2.m5282a(substring, trim);
                    }
                }
                aVar.f12952u = aVar2.m5285d();
            } else if (annotation instanceof InterfaceC4997l) {
                if (aVar.f12949r) {
                    throw C4984d0.m5663j(aVar.f12935d, "Only one encoding annotation is allowed.", new Object[0]);
                }
                aVar.f12950s = true;
            } else if (!(annotation instanceof InterfaceC4990e)) {
                continue;
            } else {
                if (aVar.f12950s) {
                    throw C4984d0.m5663j(aVar.f12935d, "Only one encoding annotation is allowed.", new Object[0]);
                }
                aVar.f12949r = true;
            }
        }
        if (aVar.f12947p == null) {
            throw C4984d0.m5663j(aVar.f12935d, "HTTP method annotation is required (e.g., @GET, @POST, etc.).", new Object[0]);
        }
        if (!aVar.f12948q) {
            if (aVar.f12950s) {
                throw C4984d0.m5663j(aVar.f12935d, "Multipart can only be specified on HTTP methods with request body (e.g., @POST).", new Object[0]);
            }
            if (aVar.f12949r) {
                throw C4984d0.m5663j(aVar.f12935d, "FormUrlEncoded can only be specified on HTTP methods with request body (e.g., @POST).", new Object[0]);
            }
        }
        int length = aVar.f12937f.length;
        aVar.f12955x = new AbstractC5026u[length];
        int i8 = length - 1;
        int i9 = 0;
        while (i9 < length) {
            AbstractC5026u<?>[] abstractC5026uArr = aVar.f12955x;
            Type type = aVar.f12938g[i9];
            Annotation[] annotationArr = aVar.f12937f[i9];
            boolean z2 = i9 == i8;
            if (annotationArr != null) {
                int length2 = annotationArr.length;
                abstractC5026u = null;
                int i10 = 0;
                while (i10 < length2) {
                    Annotation annotation2 = annotationArr[i10];
                    int i11 = length;
                    if (annotation2 instanceof InterfaceC5010y) {
                        aVar.m5683c(i9, type);
                        if (aVar.f12946o) {
                            throw C4984d0.m5665l(aVar.f12935d, i9, "Multiple @Url method annotations found.", new Object[0]);
                        }
                        if (aVar.f12942k) {
                            throw C4984d0.m5665l(aVar.f12935d, i9, "@Path parameters may not be used with @Url.", new Object[0]);
                        }
                        if (aVar.f12943l) {
                            throw C4984d0.m5665l(aVar.f12935d, i9, "A @Url parameter must not come after a @Query.", new Object[0]);
                        }
                        if (aVar.f12944m) {
                            throw C4984d0.m5665l(aVar.f12935d, i9, "A @Url parameter must not come after a @QueryName.", new Object[0]);
                        }
                        if (aVar.f12945n) {
                            throw C4984d0.m5665l(aVar.f12935d, i9, "A @Url parameter must not come after a @QueryMap.", new Object[0]);
                        }
                        if (aVar.f12951t != null) {
                            throw C4984d0.m5665l(aVar.f12935d, i9, "@Url cannot be used with @%s URL", aVar.f12947p);
                        }
                        aVar.f12946o = true;
                        if (type != C4489z.class && type != String.class && type != URI.class && (!(type instanceof Class) || !"android.net.Uri".equals(((Class) type).getName()))) {
                            throw C4984d0.m5665l(aVar.f12935d, i9, "@Url must be okhttp3.HttpUrl, String, java.net.URI, or android.net.Uri type.", new Object[0]);
                        }
                        abstractC5026u2 = new AbstractC5026u.n(aVar.f12935d, i9);
                        i4 = i8;
                        i5 = i10;
                        i7 = length2;
                    } else {
                        i4 = i8;
                        if (annotation2 instanceof InterfaceC5004s) {
                            aVar.m5683c(i9, type);
                            if (aVar.f12943l) {
                                throw C4984d0.m5665l(aVar.f12935d, i9, "A @Path parameter must not come after a @Query.", new Object[0]);
                            }
                            if (aVar.f12944m) {
                                throw C4984d0.m5665l(aVar.f12935d, i9, "A @Path parameter must not come after a @QueryName.", new Object[0]);
                            }
                            if (aVar.f12945n) {
                                throw C4984d0.m5665l(aVar.f12935d, i9, "A @Path parameter must not come after a @QueryMap.", new Object[0]);
                            }
                            if (aVar.f12946o) {
                                throw C4984d0.m5665l(aVar.f12935d, i9, "@Path parameters may not be used with @Url.", new Object[0]);
                            }
                            if (aVar.f12951t == null) {
                                throw C4984d0.m5665l(aVar.f12935d, i9, "@Path can only be used with relative url on @%s", aVar.f12947p);
                            }
                            aVar.f12942k = true;
                            InterfaceC5004s interfaceC5004s = (InterfaceC5004s) annotation2;
                            String value2 = interfaceC5004s.value();
                            if (!C5029x.a.f12933b.matcher(value2).matches()) {
                                throw C4984d0.m5665l(aVar.f12935d, i9, "@Path parameter name must match %s. Found: %s", C5029x.a.f12932a.pattern(), value2);
                            }
                            if (!aVar.f12954w.contains(value2)) {
                                throw C4984d0.m5665l(aVar.f12935d, i9, "URL \"%s\" does not contain \"{%s}\".", aVar.f12951t, value2);
                            }
                            i5 = i10;
                            i6 = length2;
                            gVar = new AbstractC5026u.i<>(aVar.f12935d, i9, value2, aVar.f12934c.m5691f(type, annotationArr), interfaceC5004s.encoded());
                        } else {
                            i5 = i10;
                            i6 = length2;
                            if (annotation2 instanceof InterfaceC5005t) {
                                aVar.m5683c(i9, type);
                                InterfaceC5005t interfaceC5005t = (InterfaceC5005t) annotation2;
                                String value3 = interfaceC5005t.value();
                                boolean encoded = interfaceC5005t.encoded();
                                Class<?> m5659f = C4984d0.m5659f(type);
                                aVar.f12943l = true;
                                if (Iterable.class.isAssignableFrom(m5659f)) {
                                    if (!(type instanceof ParameterizedType)) {
                                        throw C4984d0.m5665l(aVar.f12935d, i9, C1499a.m625k(m5659f, new StringBuilder(), " must include generic type (e.g., ", "<String>)"), new Object[0]);
                                    }
                                    gVar = new C5024s<>(new AbstractC5026u.j(value3, aVar.f12934c.m5691f(C4984d0.m5658e(0, (ParameterizedType) type), annotationArr), encoded));
                                } else if (m5659f.isArray()) {
                                    gVar = new C5025t(new AbstractC5026u.j(value3, aVar.f12934c.m5691f(C5029x.a.m5681a(m5659f.getComponentType()), annotationArr), encoded));
                                } else {
                                    bVar = new AbstractC5026u.j<>(value3, aVar.f12934c.m5691f(type, annotationArr), encoded);
                                    i7 = i6;
                                    abstractC5026u2 = bVar;
                                }
                            } else if (annotation2 instanceof InterfaceC5007v) {
                                aVar.m5683c(i9, type);
                                boolean encoded2 = ((InterfaceC5007v) annotation2).encoded();
                                Class<?> m5659f2 = C4984d0.m5659f(type);
                                aVar.f12944m = true;
                                if (Iterable.class.isAssignableFrom(m5659f2)) {
                                    if (!(type instanceof ParameterizedType)) {
                                        throw C4984d0.m5665l(aVar.f12935d, i9, C1499a.m625k(m5659f2, new StringBuilder(), " must include generic type (e.g., ", "<String>)"), new Object[0]);
                                    }
                                    gVar = new C5024s<>(new AbstractC5026u.l(aVar.f12934c.m5691f(C4984d0.m5658e(0, (ParameterizedType) type), annotationArr), encoded2));
                                } else if (m5659f2.isArray()) {
                                    gVar = new C5025t(new AbstractC5026u.l(aVar.f12934c.m5691f(C5029x.a.m5681a(m5659f2.getComponentType()), annotationArr), encoded2));
                                } else {
                                    cVar = new AbstractC5026u.l<>(aVar.f12934c.m5691f(type, annotationArr), encoded2);
                                    i7 = i6;
                                    abstractC5026u2 = cVar;
                                }
                            } else {
                                if (annotation2 instanceof InterfaceC5006u) {
                                    aVar.m5683c(i9, type);
                                    Class<?> m5659f3 = C4984d0.m5659f(type);
                                    aVar.f12945n = true;
                                    if (!Map.class.isAssignableFrom(m5659f3)) {
                                        throw C4984d0.m5665l(aVar.f12935d, i9, "@QueryMap parameter type must be Map.", new Object[0]);
                                    }
                                    Type m5660g = C4984d0.m5660g(type, m5659f3, Map.class);
                                    if (!(m5660g instanceof ParameterizedType)) {
                                        throw C4984d0.m5665l(aVar.f12935d, i9, "Map must include generic types (e.g., Map<String, String>)", new Object[0]);
                                    }
                                    ParameterizedType parameterizedType = (ParameterizedType) m5660g;
                                    Type m5658e = C4984d0.m5658e(0, parameterizedType);
                                    if (String.class != m5658e) {
                                        throw C4984d0.m5665l(aVar.f12935d, i9, C1499a.m640z("@QueryMap keys must be of type String: ", m5658e), new Object[0]);
                                    }
                                    cVar = new AbstractC5026u.k<>(aVar.f12935d, i9, aVar.f12934c.m5691f(C4984d0.m5658e(1, parameterizedType), annotationArr), ((InterfaceC5006u) annotation2).encoded());
                                } else if (annotation2 instanceof InterfaceC4994i) {
                                    aVar.m5683c(i9, type);
                                    String value4 = ((InterfaceC4994i) annotation2).value();
                                    Class<?> m5659f4 = C4984d0.m5659f(type);
                                    if (Iterable.class.isAssignableFrom(m5659f4)) {
                                        if (!(type instanceof ParameterizedType)) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, C1499a.m625k(m5659f4, new StringBuilder(), " must include generic type (e.g., ", "<String>)"), new Object[0]);
                                        }
                                        gVar = new C5024s<>(new AbstractC5026u.d(value4, aVar.f12934c.m5691f(C4984d0.m5658e(0, (ParameterizedType) type), annotationArr)));
                                    } else if (m5659f4.isArray()) {
                                        gVar = new C5025t(new AbstractC5026u.d(value4, aVar.f12934c.m5691f(C5029x.a.m5681a(m5659f4.getComponentType()), annotationArr)));
                                    } else {
                                        cVar = new AbstractC5026u.d<>(value4, aVar.f12934c.m5691f(type, annotationArr));
                                    }
                                } else if (annotation2 instanceof InterfaceC4995j) {
                                    if (type == C4488y.class) {
                                        gVar = new AbstractC5026u.f(aVar.f12935d, i9);
                                    } else {
                                        aVar.m5683c(i9, type);
                                        Class<?> m5659f5 = C4984d0.m5659f(type);
                                        if (!Map.class.isAssignableFrom(m5659f5)) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, "@HeaderMap parameter type must be Map.", new Object[0]);
                                        }
                                        Type m5660g2 = C4984d0.m5660g(type, m5659f5, Map.class);
                                        if (!(m5660g2 instanceof ParameterizedType)) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, "Map must include generic types (e.g., Map<String, String>)", new Object[0]);
                                        }
                                        ParameterizedType parameterizedType2 = (ParameterizedType) m5660g2;
                                        Type m5658e2 = C4984d0.m5658e(0, parameterizedType2);
                                        if (String.class != m5658e2) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, C1499a.m640z("@HeaderMap keys must be of type String: ", m5658e2), new Object[0]);
                                        }
                                        c5025t = new AbstractC5026u.e<>(aVar.f12935d, i9, aVar.f12934c.m5691f(C4984d0.m5658e(1, parameterizedType2), annotationArr));
                                        i7 = i6;
                                        abstractC5026u2 = c5025t;
                                    }
                                } else if (annotation2 instanceof InterfaceC4988c) {
                                    aVar.m5683c(i9, type);
                                    if (!aVar.f12949r) {
                                        throw C4984d0.m5665l(aVar.f12935d, i9, "@Field parameters can only be used with form encoding.", new Object[0]);
                                    }
                                    InterfaceC4988c interfaceC4988c = (InterfaceC4988c) annotation2;
                                    String value5 = interfaceC4988c.value();
                                    boolean encoded3 = interfaceC4988c.encoded();
                                    aVar.f12939h = true;
                                    Class<?> m5659f6 = C4984d0.m5659f(type);
                                    if (Iterable.class.isAssignableFrom(m5659f6)) {
                                        if (!(type instanceof ParameterizedType)) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, C1499a.m625k(m5659f6, new StringBuilder(), " must include generic type (e.g., ", "<String>)"), new Object[0]);
                                        }
                                        gVar = new C5024s<>(new AbstractC5026u.b(value5, aVar.f12934c.m5691f(C4984d0.m5658e(0, (ParameterizedType) type), annotationArr), encoded3));
                                    } else if (m5659f6.isArray()) {
                                        gVar = new C5025t(new AbstractC5026u.b(value5, aVar.f12934c.m5691f(C5029x.a.m5681a(m5659f6.getComponentType()), annotationArr), encoded3));
                                    } else {
                                        bVar = new AbstractC5026u.b<>(value5, aVar.f12934c.m5691f(type, annotationArr), encoded3);
                                        i7 = i6;
                                        abstractC5026u2 = bVar;
                                    }
                                } else if (annotation2 instanceof InterfaceC4989d) {
                                    aVar.m5683c(i9, type);
                                    if (!aVar.f12949r) {
                                        throw C4984d0.m5665l(aVar.f12935d, i9, "@FieldMap parameters can only be used with form encoding.", new Object[0]);
                                    }
                                    Class<?> m5659f7 = C4984d0.m5659f(type);
                                    if (!Map.class.isAssignableFrom(m5659f7)) {
                                        throw C4984d0.m5665l(aVar.f12935d, i9, "@FieldMap parameter type must be Map.", new Object[0]);
                                    }
                                    Type m5660g3 = C4984d0.m5660g(type, m5659f7, Map.class);
                                    if (!(m5660g3 instanceof ParameterizedType)) {
                                        throw C4984d0.m5665l(aVar.f12935d, i9, "Map must include generic types (e.g., Map<String, String>)", new Object[0]);
                                    }
                                    ParameterizedType parameterizedType3 = (ParameterizedType) m5660g3;
                                    Type m5658e3 = C4984d0.m5658e(0, parameterizedType3);
                                    if (String.class != m5658e3) {
                                        throw C4984d0.m5665l(aVar.f12935d, i9, C1499a.m640z("@FieldMap keys must be of type String: ", m5658e3), new Object[0]);
                                    }
                                    InterfaceC5013h<T, String> m5691f = aVar.f12934c.m5691f(C4984d0.m5658e(1, parameterizedType3), annotationArr);
                                    aVar.f12939h = true;
                                    cVar = new AbstractC5026u.c<>(aVar.f12935d, i9, m5691f, ((InterfaceC4989d) annotation2).encoded());
                                } else if (annotation2 instanceof InterfaceC5002q) {
                                    aVar.m5683c(i9, type);
                                    if (!aVar.f12950s) {
                                        throw C4984d0.m5665l(aVar.f12935d, i9, "@Part parameters can only be used with multipart encoding.", new Object[0]);
                                    }
                                    InterfaceC5002q interfaceC5002q = (InterfaceC5002q) annotation2;
                                    aVar.f12940i = true;
                                    String value6 = interfaceC5002q.value();
                                    Class<?> m5659f8 = C4984d0.m5659f(type);
                                    if (value6.isEmpty()) {
                                        if (Iterable.class.isAssignableFrom(m5659f8)) {
                                            if (!(type instanceof ParameterizedType)) {
                                                throw C4984d0.m5665l(aVar.f12935d, i9, C1499a.m625k(m5659f8, new StringBuilder(), " must include generic type (e.g., ", "<String>)"), new Object[0]);
                                            }
                                            if (!C4373c0.b.class.isAssignableFrom(C4984d0.m5659f(C4984d0.m5658e(0, (ParameterizedType) type)))) {
                                                throw C4984d0.m5665l(aVar.f12935d, i9, "@Part annotation must supply a name or use MultipartBody.Part parameter type.", new Object[0]);
                                            }
                                            c5025t = new C5024s<>(AbstractC5026u.m.f12898a);
                                        } else if (m5659f8.isArray()) {
                                            if (!C4373c0.b.class.isAssignableFrom(m5659f8.getComponentType())) {
                                                throw C4984d0.m5665l(aVar.f12935d, i9, "@Part annotation must supply a name or use MultipartBody.Part parameter type.", new Object[0]);
                                            }
                                            c5025t = new C5025t(AbstractC5026u.m.f12898a);
                                        } else {
                                            if (!C4373c0.b.class.isAssignableFrom(m5659f8)) {
                                                throw C4984d0.m5665l(aVar.f12935d, i9, "@Part annotation must supply a name or use MultipartBody.Part parameter type.", new Object[0]);
                                            }
                                            gVar = AbstractC5026u.m.f12898a;
                                        }
                                        i7 = i6;
                                        abstractC5026u2 = c5025t;
                                    } else {
                                        i7 = i6;
                                        C4488y m5290c = C4488y.f12040c.m5290c("Content-Disposition", C1499a.m639y("form-data; name=\"", value6, "\""), "Content-Transfer-Encoding", interfaceC5002q.encoding());
                                        if (Iterable.class.isAssignableFrom(m5659f8)) {
                                            if (!(type instanceof ParameterizedType)) {
                                                throw C4984d0.m5665l(aVar.f12935d, i9, C1499a.m625k(m5659f8, new StringBuilder(), " must include generic type (e.g., ", "<String>)"), new Object[0]);
                                            }
                                            Type m5658e4 = C4984d0.m5658e(0, (ParameterizedType) type);
                                            if (C4373c0.b.class.isAssignableFrom(C4984d0.m5659f(m5658e4))) {
                                                throw C4984d0.m5665l(aVar.f12935d, i9, "@Part parameters using the MultipartBody.Part must not include a part name in the annotation.", new Object[0]);
                                            }
                                            abstractC5026u2 = new C5024s<>(new AbstractC5026u.g(aVar.f12935d, i9, m5290c, aVar.f12934c.m5689d(m5658e4, annotationArr, aVar.f12936e)));
                                        } else if (m5659f8.isArray()) {
                                            Class<?> m5681a = C5029x.a.m5681a(m5659f8.getComponentType());
                                            if (C4373c0.b.class.isAssignableFrom(m5681a)) {
                                                throw C4984d0.m5665l(aVar.f12935d, i9, "@Part parameters using the MultipartBody.Part must not include a part name in the annotation.", new Object[0]);
                                            }
                                            abstractC5026u2 = new C5025t(new AbstractC5026u.g(aVar.f12935d, i9, m5290c, aVar.f12934c.m5689d(m5681a, annotationArr, aVar.f12936e)));
                                        } else {
                                            if (C4373c0.b.class.isAssignableFrom(m5659f8)) {
                                                throw C4984d0.m5665l(aVar.f12935d, i9, "@Part parameters using the MultipartBody.Part must not include a part name in the annotation.", new Object[0]);
                                            }
                                            gVar = new AbstractC5026u.g<>(aVar.f12935d, i9, m5290c, aVar.f12934c.m5689d(type, annotationArr, aVar.f12936e));
                                            abstractC5026u2 = gVar;
                                        }
                                    }
                                } else {
                                    i7 = i6;
                                    if (annotation2 instanceof InterfaceC5003r) {
                                        aVar.m5683c(i9, type);
                                        if (!aVar.f12950s) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, "@PartMap parameters can only be used with multipart encoding.", new Object[0]);
                                        }
                                        aVar.f12940i = true;
                                        Class<?> m5659f9 = C4984d0.m5659f(type);
                                        if (!Map.class.isAssignableFrom(m5659f9)) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, "@PartMap parameter type must be Map.", new Object[0]);
                                        }
                                        Type m5660g4 = C4984d0.m5660g(type, m5659f9, Map.class);
                                        if (!(m5660g4 instanceof ParameterizedType)) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, "Map must include generic types (e.g., Map<String, String>)", new Object[0]);
                                        }
                                        ParameterizedType parameterizedType4 = (ParameterizedType) m5660g4;
                                        Type m5658e5 = C4984d0.m5658e(0, parameterizedType4);
                                        if (String.class != m5658e5) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, C1499a.m640z("@PartMap keys must be of type String: ", m5658e5), new Object[0]);
                                        }
                                        Type m5658e6 = C4984d0.m5658e(1, parameterizedType4);
                                        if (C4373c0.b.class.isAssignableFrom(C4984d0.m5659f(m5658e6))) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, "@PartMap values cannot be MultipartBody.Part. Use @Part List<Part> or a different value type instead.", new Object[0]);
                                        }
                                        abstractC5026u2 = new AbstractC5026u.h<>(aVar.f12935d, i9, aVar.f12934c.m5689d(m5658e6, annotationArr, aVar.f12936e), ((InterfaceC5003r) annotation2).encoding());
                                    } else if (annotation2 instanceof InterfaceC4986a) {
                                        aVar.m5683c(i9, type);
                                        if (aVar.f12949r || aVar.f12950s) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, "@Body parameters cannot be used with form or multi-part encoding.", new Object[0]);
                                        }
                                        if (aVar.f12941j) {
                                            throw C4984d0.m5665l(aVar.f12935d, i9, "Multiple @Body method annotations found.", new Object[0]);
                                        }
                                        try {
                                            InterfaceC5013h<T, AbstractC4387j0> m5689d = aVar.f12934c.m5689d(type, annotationArr, aVar.f12936e);
                                            aVar.f12941j = true;
                                            abstractC5026u2 = new AbstractC5026u.a<>(aVar.f12935d, i9, m5689d);
                                        } catch (RuntimeException e3) {
                                            throw C4984d0.m5666m(aVar.f12935d, e3, i9, "Unable to create @Body converter for %s", type);
                                        }
                                    } else if (annotation2 instanceof InterfaceC5009x) {
                                        aVar.m5683c(i9, type);
                                        Class<?> m5659f10 = C4984d0.m5659f(type);
                                        for (int i12 = i9 - 1; i12 >= 0; i12--) {
                                            AbstractC5026u<?> abstractC5026u3 = aVar.f12955x[i12];
                                            if ((abstractC5026u3 instanceof AbstractC5026u.o) && ((AbstractC5026u.o) abstractC5026u3).f12901a.equals(m5659f10)) {
                                                Method method2 = aVar.f12935d;
                                                StringBuilder m586H = C1499a.m586H("@Tag type ");
                                                m586H.append(m5659f10.getName());
                                                m586H.append(" is duplicate of parameter #");
                                                m586H.append(i12 + 1);
                                                m586H.append(" and would always overwrite its value.");
                                                throw C4984d0.m5665l(method2, i9, m586H.toString(), new Object[0]);
                                            }
                                        }
                                        abstractC5026u2 = new AbstractC5026u.o<>(m5659f10);
                                    } else {
                                        abstractC5026u2 = null;
                                    }
                                }
                                i7 = i6;
                                abstractC5026u2 = cVar;
                            }
                        }
                        i7 = i6;
                        abstractC5026u2 = gVar;
                    }
                    if (abstractC5026u2 != null) {
                        if (abstractC5026u != null) {
                            throw C4984d0.m5665l(aVar.f12935d, i9, "Multiple Retrofit annotations found, only one allowed.", new Object[0]);
                        }
                        abstractC5026u = abstractC5026u2;
                    }
                    i10 = i5 + 1;
                    length = i11;
                    i8 = i4;
                    length2 = i7;
                }
                i2 = length;
                i3 = i8;
            } else {
                i2 = length;
                i3 = i8;
                abstractC5026u = null;
            }
            if (abstractC5026u == null) {
                if (z2) {
                    try {
                        if (C4984d0.m5659f(type) == Continuation.class) {
                            aVar.f12956y = true;
                            abstractC5026u = null;
                        }
                    } catch (NoClassDefFoundError unused) {
                    }
                }
                throw C4984d0.m5665l(aVar.f12935d, i9, "No Retrofit annotation found.", new Object[0]);
            }
            abstractC5026uArr[i9] = abstractC5026u;
            i9++;
            length = i2;
            i8 = i3;
        }
        if (aVar.f12951t == null && !aVar.f12946o) {
            throw C4984d0.m5663j(aVar.f12935d, "Missing either @%s URL or @Url parameter.", aVar.f12947p);
        }
        boolean z3 = aVar.f12949r;
        if (!z3 && !aVar.f12950s && !aVar.f12948q && aVar.f12941j) {
            throw C4984d0.m5663j(aVar.f12935d, "Non-body HTTP method cannot contain @Body.", new Object[0]);
        }
        if (z3 && !aVar.f12939h) {
            throw C4984d0.m5663j(aVar.f12935d, "Form-encoded method must contain at least one @Field.", new Object[0]);
        }
        if (aVar.f12950s && !aVar.f12940i) {
            throw C4984d0.m5663j(aVar.f12935d, "Multipart method must contain at least one @Part.", new Object[0]);
        }
        C5029x c5029x = new C5029x(aVar);
        Type genericReturnType2 = method.getGenericReturnType();
        if (C4984d0.m5661h(genericReturnType2)) {
            throw C4984d0.m5663j(method, "Method return type must not include a type variable or wildcard: %s", genericReturnType2);
        }
        if (genericReturnType2 == Void.TYPE) {
            throw C4984d0.m5663j(method, "Service methods cannot return void.", new Object[0]);
        }
        boolean z4 = c5029x.f12931k;
        Annotation[] annotations = method.getAnnotations();
        if (z4) {
            Type type2 = ((ParameterizedType) method.getGenericParameterTypes()[r5.length - 1]).getActualTypeArguments()[0];
            if (type2 instanceof WildcardType) {
                type2 = ((WildcardType) type2).getLowerBounds()[0];
            }
            if (C4984d0.m5659f(type2) == C5030y.class && (type2 instanceof ParameterizedType)) {
                type2 = C4984d0.m5658e(0, (ParameterizedType) type2);
                z = true;
            } else {
                z = false;
            }
            genericReturnType = new C4984d0.b(null, InterfaceC4983d.class, type2);
            if (!C4984d0.m5662i(annotations, InterfaceC4980b0.class)) {
                Annotation[] annotationArr2 = new Annotation[annotations.length + 1];
                annotationArr2[0] = C4982c0.f12806a;
                System.arraycopy(annotations, 0, annotationArr2, 1, annotations.length);
                annotations = annotationArr2;
            }
        } else {
            genericReturnType = method.getGenericReturnType();
            z = false;
        }
        try {
            InterfaceC4985e<?, ?> m5686a = c5031z.m5686a(genericReturnType, annotations);
            Type mo277a = m5686a.mo277a();
            if (mo277a == C4389k0.class) {
                StringBuilder m586H2 = C1499a.m586H("'");
                m586H2.append(C4984d0.m5659f(mo277a).getName());
                m586H2.append("' is not a valid response body type. Did you mean ResponseBody?");
                throw C4984d0.m5663j(method, m586H2.toString(), new Object[0]);
            }
            if (mo277a == C5030y.class) {
                throw C4984d0.m5663j(method, "Response must include generic type (e.g., Response<String>)", new Object[0]);
            }
            if (c5029x.f12923c.equals("HEAD") && !Void.class.equals(mo277a)) {
                throw C4984d0.m5663j(method, "HEAD method must use Void as response type.", new Object[0]);
            }
            try {
                InterfaceC5013h<AbstractC4393m0, T> m5690e = c5031z.m5690e(mo277a, method.getAnnotations());
                InterfaceC4378f.a aVar4 = c5031z.f12960b;
                return !z4 ? new AbstractC5016k.a(c5029x, aVar4, m5690e, m5686a) : z ? new AbstractC5016k.c(c5029x, aVar4, m5690e, m5686a) : new AbstractC5016k.b(c5029x, aVar4, m5690e, m5686a, false);
            } catch (RuntimeException e4) {
                throw C4984d0.m5664k(method, e4, "Unable to create converter for %s", mo277a);
            }
        } catch (RuntimeException e5) {
            throw C4984d0.m5664k(method, e5, "Unable to create call adapter for %s", genericReturnType);
        }
    }

    @Nullable
    /* renamed from: a */
    public abstract T mo5649a(Object[] objArr);
}
