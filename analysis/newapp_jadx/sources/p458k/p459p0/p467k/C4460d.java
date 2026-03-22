package p458k.p459p0.p467k;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLSocket;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.EnumC4377e0;

/* renamed from: k.p0.k.d */
/* loaded from: classes3.dex */
public final class C4460d extends C4463g {

    /* renamed from: d */
    public final Method f11973d;

    /* renamed from: e */
    public final Method f11974e;

    /* renamed from: f */
    public final Method f11975f;

    /* renamed from: g */
    public final Class<?> f11976g;

    /* renamed from: h */
    public final Class<?> f11977h;

    /* renamed from: k.p0.k.d$a */
    public static final class a implements InvocationHandler {

        /* renamed from: c */
        public boolean f11978c;

        /* renamed from: e */
        @Nullable
        public String f11979e;

        /* renamed from: f */
        public final List<String> f11980f;

        public a(@NotNull List<String> protocols) {
            Intrinsics.checkParameterIsNotNull(protocols, "protocols");
            this.f11980f = protocols;
        }

        @Override // java.lang.reflect.InvocationHandler
        @Nullable
        public Object invoke(@NotNull Object proxy, @NotNull Method method, @Nullable Object[] objArr) {
            Intrinsics.checkParameterIsNotNull(proxy, "proxy");
            Intrinsics.checkParameterIsNotNull(method, "method");
            if (objArr == null) {
                objArr = new Object[0];
            }
            String name = method.getName();
            Class<?> returnType = method.getReturnType();
            if (Intrinsics.areEqual(name, "supports") && Intrinsics.areEqual(Boolean.TYPE, returnType)) {
                return Boolean.TRUE;
            }
            if (Intrinsics.areEqual(name, "unsupported") && Intrinsics.areEqual(Void.TYPE, returnType)) {
                this.f11978c = true;
                return null;
            }
            if (Intrinsics.areEqual(name, "protocols")) {
                if (objArr.length == 0) {
                    return this.f11980f;
                }
            }
            if ((!Intrinsics.areEqual(name, "selectProtocol") && !Intrinsics.areEqual(name, "select")) || !Intrinsics.areEqual(String.class, returnType) || objArr.length != 1 || !(objArr[0] instanceof List)) {
                if ((!Intrinsics.areEqual(name, "protocolSelected") && !Intrinsics.areEqual(name, "selected")) || objArr.length != 1) {
                    return method.invoke(this, Arrays.copyOf(objArr, objArr.length));
                }
                Object obj = objArr[0];
                if (obj == null) {
                    throw new TypeCastException("null cannot be cast to non-null type kotlin.String");
                }
                this.f11979e = (String) obj;
                return null;
            }
            Object obj2 = objArr[0];
            if (obj2 == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.collections.List<*>");
            }
            List list = (List) obj2;
            int size = list.size();
            if (size >= 0) {
                int i2 = 0;
                while (true) {
                    Object obj3 = list.get(i2);
                    if (obj3 == null) {
                        throw new TypeCastException("null cannot be cast to non-null type kotlin.String");
                    }
                    String str = (String) obj3;
                    if (!this.f11980f.contains(str)) {
                        if (i2 == size) {
                            break;
                        }
                        i2++;
                    } else {
                        this.f11979e = str;
                        return str;
                    }
                }
            }
            String str2 = this.f11980f.get(0);
            this.f11979e = str2;
            return str2;
        }
    }

    public C4460d(@NotNull Method putMethod, @NotNull Method getMethod, @NotNull Method removeMethod, @NotNull Class<?> clientProviderClass, @NotNull Class<?> serverProviderClass) {
        Intrinsics.checkParameterIsNotNull(putMethod, "putMethod");
        Intrinsics.checkParameterIsNotNull(getMethod, "getMethod");
        Intrinsics.checkParameterIsNotNull(removeMethod, "removeMethod");
        Intrinsics.checkParameterIsNotNull(clientProviderClass, "clientProviderClass");
        Intrinsics.checkParameterIsNotNull(serverProviderClass, "serverProviderClass");
        this.f11973d = putMethod;
        this.f11974e = getMethod;
        this.f11975f = removeMethod;
        this.f11976g = clientProviderClass;
        this.f11977h = serverProviderClass;
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: a */
    public void mo5247a(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        try {
            this.f11975f.invoke(null, sslSocket);
        } catch (IllegalAccessException e2) {
            throw new AssertionError("failed to remove ALPN", e2);
        } catch (InvocationTargetException e3) {
            throw new AssertionError("failed to remove ALPN", e3);
        }
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: e */
    public void mo5233e(@NotNull SSLSocket sslSocket, @Nullable String str, @NotNull List<? extends EnumC4377e0> protocols) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        ArrayList arrayList = new ArrayList();
        Iterator<T> it = protocols.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            Object next = it.next();
            if (((EnumC4377e0) next) != EnumC4377e0.HTTP_1_0) {
                arrayList.add(next);
            }
        }
        ArrayList arrayList2 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(((EnumC4377e0) it2.next()).f11430l);
        }
        try {
            this.f11973d.invoke(null, sslSocket, Proxy.newProxyInstance(C4463g.class.getClassLoader(), new Class[]{this.f11976g, this.f11977h}, new a(arrayList2)));
        } catch (IllegalAccessException e2) {
            throw new AssertionError("failed to set ALPN", e2);
        } catch (InvocationTargetException e3) {
            throw new AssertionError("failed to set ALPN", e3);
        }
    }

    @Override // p458k.p459p0.p467k.C4463g
    @Nullable
    /* renamed from: h */
    public String mo5234h(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        try {
            InvocationHandler invocationHandler = Proxy.getInvocationHandler(this.f11974e.invoke(null, sslSocket));
            if (invocationHandler == null) {
                throw new TypeCastException("null cannot be cast to non-null type okhttp3.internal.platform.Jdk8WithJettyBootPlatform.AlpnProvider");
            }
            a aVar = (a) invocationHandler;
            boolean z = aVar.f11978c;
            if (!z && aVar.f11979e == null) {
                C4463g.m5248l(this, "ALPN callback dropped: HTTP/2 is disabled. Is alpn-boot on the boot class path?", 0, null, 6, null);
                return null;
            }
            if (z) {
                return null;
            }
            return aVar.f11979e;
        } catch (IllegalAccessException e2) {
            throw new AssertionError("failed to get ALPN selected protocol", e2);
        } catch (InvocationTargetException e3) {
            throw new AssertionError("failed to get ALPN selected protocol", e3);
        }
    }
}
