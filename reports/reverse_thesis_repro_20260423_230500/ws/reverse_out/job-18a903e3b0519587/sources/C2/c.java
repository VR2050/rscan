package C2;

import B2.C;
import B2.E;
import B2.InterfaceC0167e;
import B2.r;
import B2.t;
import B2.u;
import B2.z;
import Q2.D;
import Q2.F;
import Q2.i;
import Q2.k;
import Q2.l;
import Q2.w;
import h2.AbstractC0555a;
import i2.AbstractC0580h;
import i2.AbstractC0586n;
import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import q2.AbstractC0663a;
import t2.j;
import z2.d;
import z2.f;
import z2.g;

/* JADX INFO: loaded from: classes.dex */
public abstract class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final byte[] f578a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final t f579b = t.f410c.h(new String[0]);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final E f580c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final C f581d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final w f582e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final TimeZone f583f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final f f584g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final boolean f585h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final String f586i;

    static final class a implements r.c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ r f587a;

        a(r rVar) {
            this.f587a = rVar;
        }

        @Override // B2.r.c
        public final r a(InterfaceC0167e interfaceC0167e) {
            j.f(interfaceC0167e, "it");
            return this.f587a;
        }
    }

    static final class b implements ThreadFactory {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ String f588a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ boolean f589b;

        b(String str, boolean z3) {
            this.f588a = str;
            this.f589b = z3;
        }

        @Override // java.util.concurrent.ThreadFactory
        public final Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, this.f588a);
            thread.setDaemon(this.f589b);
            return thread;
        }
    }

    static {
        byte[] bArr = new byte[0];
        f578a = bArr;
        f580c = E.a.d(E.f131b, bArr, null, 1, null);
        f581d = C.a.h(C.f97a, bArr, null, 0, 0, 7, null);
        w.a aVar = w.f2578e;
        l.a aVar2 = l.f2556f;
        f582e = aVar.d(aVar2.c("efbbbf"), aVar2.c("feff"), aVar2.c("fffe"), aVar2.c("0000ffff"), aVar2.c("ffff0000"));
        TimeZone timeZone = TimeZone.getTimeZone("GMT");
        j.c(timeZone);
        f583f = timeZone;
        f584g = new f("([0-9a-fA-F]*:[0-9a-fA-F:.]*)|([\\d.]+)");
        f585h = false;
        String name = z.class.getName();
        j.e(name, "OkHttpClient::class.java.name");
        f586i = g.Z(g.Y(name, "okhttp3."), "Client");
    }

    public static final int A(String str, int i3) {
        j.f(str, "$this$indexOfNonWhitespace");
        int length = str.length();
        while (i3 < length) {
            char cCharAt = str.charAt(i3);
            if (cCharAt != ' ' && cCharAt != '\t') {
                return i3;
            }
            i3++;
        }
        return str.length();
    }

    public static final String[] B(String[] strArr, String[] strArr2, Comparator comparator) {
        j.f(strArr, "$this$intersect");
        j.f(strArr2, "other");
        j.f(comparator, "comparator");
        ArrayList arrayList = new ArrayList();
        for (String str : strArr) {
            int length = strArr2.length;
            int i3 = 0;
            while (true) {
                if (i3 >= length) {
                    break;
                }
                if (comparator.compare(str, strArr2[i3]) == 0) {
                    arrayList.add(str);
                    break;
                }
                i3++;
            }
        }
        Object[] array = arrayList.toArray(new String[0]);
        if (array != null) {
            return (String[]) array;
        }
        throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
    }

    public static final boolean C(K2.a aVar, File file) throws IOException {
        j.f(aVar, "$this$isCivilized");
        j.f(file, "file");
        D dC = aVar.c(file);
        try {
            try {
                aVar.a(file);
                AbstractC0663a.a(dC, null);
                return true;
            } catch (IOException unused) {
                h2.r rVar = h2.r.f9288a;
                AbstractC0663a.a(dC, null);
                aVar.a(file);
                return false;
            }
        } finally {
        }
    }

    public static final boolean D(Socket socket, k kVar) {
        j.f(socket, "$this$isHealthy");
        j.f(kVar, "source");
        try {
            int soTimeout = socket.getSoTimeout();
            try {
                socket.setSoTimeout(1);
                boolean z3 = !kVar.K();
                socket.setSoTimeout(soTimeout);
                return z3;
            } catch (Throwable th) {
                socket.setSoTimeout(soTimeout);
                throw th;
            }
        } catch (SocketTimeoutException unused) {
            return true;
        } catch (IOException unused2) {
            return false;
        }
    }

    public static final boolean E(String str) {
        j.f(str, "name");
        return g.j(str, "Authorization", true) || g.j(str, "Cookie", true) || g.j(str, "Proxy-Authorization", true) || g.j(str, "Set-Cookie", true);
    }

    public static final int F(char c3) {
        if ('0' <= c3 && '9' >= c3) {
            return c3 - '0';
        }
        if ('a' <= c3 && 'f' >= c3) {
            return c3 - 'W';
        }
        if ('A' <= c3 && 'F' >= c3) {
            return c3 - '7';
        }
        return -1;
    }

    public static final Charset G(k kVar, Charset charset) {
        j.f(kVar, "$this$readBomAsCharset");
        j.f(charset, "default");
        int iC0 = kVar.c0(f582e);
        if (iC0 == -1) {
            return charset;
        }
        if (iC0 == 0) {
            Charset charset2 = StandardCharsets.UTF_8;
            j.e(charset2, "UTF_8");
            return charset2;
        }
        if (iC0 == 1) {
            Charset charset3 = StandardCharsets.UTF_16BE;
            j.e(charset3, "UTF_16BE");
            return charset3;
        }
        if (iC0 == 2) {
            Charset charset4 = StandardCharsets.UTF_16LE;
            j.e(charset4, "UTF_16LE");
            return charset4;
        }
        if (iC0 == 3) {
            return d.f10543a.a();
        }
        if (iC0 == 4) {
            return d.f10543a.b();
        }
        throw new AssertionError();
    }

    public static final int H(k kVar) {
        j.f(kVar, "$this$readMedium");
        return b(kVar.r0(), 255) | (b(kVar.r0(), 255) << 16) | (b(kVar.r0(), 255) << 8);
    }

    public static final int I(i iVar, byte b3) throws EOFException {
        j.f(iVar, "$this$skipAll");
        int i3 = 0;
        while (!iVar.K() && iVar.Z(0L) == b3) {
            i3++;
            iVar.r0();
        }
        return i3;
    }

    public static final boolean J(F f3, int i3, TimeUnit timeUnit) {
        j.f(f3, "$this$skipAll");
        j.f(timeUnit, "timeUnit");
        long jNanoTime = System.nanoTime();
        long jC = f3.f().e() ? f3.f().c() - jNanoTime : Long.MAX_VALUE;
        f3.f().d(Math.min(jC, timeUnit.toNanos(i3)) + jNanoTime);
        try {
            i iVar = new i();
            while (f3.R(iVar, 8192L) != -1) {
                iVar.v();
            }
            if (jC == Long.MAX_VALUE) {
                f3.f().a();
            } else {
                f3.f().d(jNanoTime + jC);
            }
            return true;
        } catch (InterruptedIOException unused) {
            if (jC == Long.MAX_VALUE) {
                f3.f().a();
            } else {
                f3.f().d(jNanoTime + jC);
            }
            return false;
        } catch (Throwable th) {
            if (jC == Long.MAX_VALUE) {
                f3.f().a();
            } else {
                f3.f().d(jNanoTime + jC);
            }
            throw th;
        }
    }

    public static final ThreadFactory K(String str, boolean z3) {
        j.f(str, "name");
        return new b(str, z3);
    }

    public static final List L(t tVar) {
        j.f(tVar, "$this$toHeaderList");
        w2.c cVarI = w2.d.i(0, tVar.size());
        ArrayList arrayList = new ArrayList(AbstractC0586n.o(cVarI, 10));
        Iterator it = cVarI.iterator();
        while (it.hasNext()) {
            int iA = ((i2.C) it).a();
            arrayList.add(new J2.c(tVar.b(iA), tVar.h(iA)));
        }
        return arrayList;
    }

    public static final t M(List list) {
        j.f(list, "$this$toHeaders");
        t.a aVar = new t.a();
        Iterator it = list.iterator();
        while (it.hasNext()) {
            J2.c cVar = (J2.c) it.next();
            aVar.c(cVar.a().z(), cVar.b().z());
        }
        return aVar.e();
    }

    public static final String N(int i3) {
        String hexString = Integer.toHexString(i3);
        j.e(hexString, "Integer.toHexString(this)");
        return hexString;
    }

    public static final String O(long j3) {
        String hexString = Long.toHexString(j3);
        j.e(hexString, "java.lang.Long.toHexString(this)");
        return hexString;
    }

    public static final String P(u uVar, boolean z3) {
        String strH;
        j.f(uVar, "$this$toHostHeader");
        if (g.z(uVar.h(), ":", false, 2, null)) {
            strH = '[' + uVar.h() + ']';
        } else {
            strH = uVar.h();
        }
        if (!z3 && uVar.l() == u.f414l.c(uVar.p())) {
            return strH;
        }
        return strH + ':' + uVar.l();
    }

    public static /* synthetic */ String Q(u uVar, boolean z3, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            z3 = false;
        }
        return P(uVar, z3);
    }

    public static final List R(List list) {
        j.f(list, "$this$toImmutableList");
        List listUnmodifiableList = Collections.unmodifiableList(AbstractC0586n.V(list));
        j.e(listUnmodifiableList, "Collections.unmodifiableList(toMutableList())");
        return listUnmodifiableList;
    }

    public static final Map S(Map map) {
        j.f(map, "$this$toImmutableMap");
        if (map.isEmpty()) {
            return i2.D.f();
        }
        Map mapUnmodifiableMap = Collections.unmodifiableMap(new LinkedHashMap(map));
        j.e(mapUnmodifiableMap, "Collections.unmodifiableMap(LinkedHashMap(this))");
        return mapUnmodifiableMap;
    }

    public static final long T(String str, long j3) {
        j.f(str, "$this$toLongOrDefault");
        try {
            return Long.parseLong(str);
        } catch (NumberFormatException unused) {
            return j3;
        }
    }

    public static final int U(String str, int i3) {
        if (str != null) {
            try {
                long j3 = Long.parseLong(str);
                if (j3 > Integer.MAX_VALUE) {
                    return Integer.MAX_VALUE;
                }
                if (j3 < 0) {
                    return 0;
                }
                return (int) j3;
            } catch (NumberFormatException unused) {
            }
        }
        return i3;
    }

    public static final String V(String str, int i3, int i4) {
        j.f(str, "$this$trimSubstring");
        int iW = w(str, i3, i4);
        String strSubstring = str.substring(iW, y(str, iW, i4));
        j.e(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        return strSubstring;
    }

    public static /* synthetic */ String W(String str, int i3, int i4, int i5, Object obj) {
        if ((i5 & 1) != 0) {
            i3 = 0;
        }
        if ((i5 & 2) != 0) {
            i4 = str.length();
        }
        return V(str, i3, i4);
    }

    public static final Throwable X(Exception exc, List list) {
        j.f(exc, "$this$withSuppressed");
        j.f(list, "suppressed");
        if (list.size() > 1) {
            System.out.println(list);
        }
        Iterator it = list.iterator();
        while (it.hasNext()) {
            AbstractC0555a.a(exc, (Exception) it.next());
        }
        return exc;
    }

    public static final void Y(Q2.j jVar, int i3) {
        j.f(jVar, "$this$writeMedium");
        jVar.L((i3 >>> 16) & 255);
        jVar.L((i3 >>> 8) & 255);
        jVar.L(i3 & 255);
    }

    public static final void a(List list, Object obj) {
        j.f(list, "$this$addIfAbsent");
        if (list.contains(obj)) {
            return;
        }
        list.add(obj);
    }

    public static final int b(byte b3, int i3) {
        return b3 & i3;
    }

    public static final int c(short s3, int i3) {
        return s3 & i3;
    }

    public static final long d(int i3, long j3) {
        return ((long) i3) & j3;
    }

    public static final r.c e(r rVar) {
        j.f(rVar, "$this$asFactory");
        return new a(rVar);
    }

    public static final boolean f(String str) {
        j.f(str, "$this$canParseAsIpAddress");
        return f584g.a(str);
    }

    public static final boolean g(u uVar, u uVar2) {
        j.f(uVar, "$this$canReuseConnectionFor");
        j.f(uVar2, "other");
        return j.b(uVar.h(), uVar2.h()) && uVar.l() == uVar2.l() && j.b(uVar.p(), uVar2.p());
    }

    public static final int h(String str, long j3, TimeUnit timeUnit) {
        j.f(str, "name");
        if (!(j3 >= 0)) {
            throw new IllegalStateException((str + " < 0").toString());
        }
        if (!(timeUnit != null)) {
            throw new IllegalStateException("unit == null");
        }
        long millis = timeUnit.toMillis(j3);
        if (!(millis <= ((long) Integer.MAX_VALUE))) {
            throw new IllegalArgumentException((str + " too large.").toString());
        }
        if (millis != 0 || j3 <= 0) {
            return (int) millis;
        }
        throw new IllegalArgumentException((str + " too small.").toString());
    }

    public static final void i(long j3, long j4, long j5) {
        if ((j4 | j5) < 0 || j4 > j3 || j3 - j4 < j5) {
            throw new ArrayIndexOutOfBoundsException();
        }
    }

    public static final void j(Closeable closeable) {
        j.f(closeable, "$this$closeQuietly");
        try {
            closeable.close();
        } catch (RuntimeException e3) {
            throw e3;
        } catch (Exception unused) {
        }
    }

    public static final void k(Socket socket) {
        j.f(socket, "$this$closeQuietly");
        try {
            socket.close();
        } catch (AssertionError e3) {
            throw e3;
        } catch (RuntimeException e4) {
            if (!j.b(e4.getMessage(), "bio == null")) {
                throw e4;
            }
        } catch (Exception unused) {
        }
    }

    public static final String[] l(String[] strArr, String str) {
        j.f(strArr, "$this$concat");
        j.f(str, "value");
        Object[] objArrCopyOf = Arrays.copyOf(strArr, strArr.length + 1);
        j.e(objArrCopyOf, "java.util.Arrays.copyOf(this, newSize)");
        String[] strArr2 = (String[]) objArrCopyOf;
        strArr2[AbstractC0580h.r(strArr2)] = str;
        return strArr2;
    }

    public static final int m(String str, char c3, int i3, int i4) {
        j.f(str, "$this$delimiterOffset");
        while (i3 < i4) {
            if (str.charAt(i3) == c3) {
                return i3;
            }
            i3++;
        }
        return i4;
    }

    public static final int n(String str, String str2, int i3, int i4) {
        j.f(str, "$this$delimiterOffset");
        j.f(str2, "delimiters");
        while (i3 < i4) {
            if (g.y(str2, str.charAt(i3), false, 2, null)) {
                return i3;
            }
            i3++;
        }
        return i4;
    }

    public static /* synthetic */ int o(String str, char c3, int i3, int i4, int i5, Object obj) {
        if ((i5 & 2) != 0) {
            i3 = 0;
        }
        if ((i5 & 4) != 0) {
            i4 = str.length();
        }
        return m(str, c3, i3, i4);
    }

    public static final boolean p(F f3, int i3, TimeUnit timeUnit) {
        j.f(f3, "$this$discard");
        j.f(timeUnit, "timeUnit");
        try {
            return J(f3, i3, timeUnit);
        } catch (IOException unused) {
            return false;
        }
    }

    public static final String q(String str, Object... objArr) {
        j.f(str, "format");
        j.f(objArr, "args");
        t2.w wVar = t2.w.f10219a;
        Locale locale = Locale.US;
        Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
        String str2 = String.format(locale, str, Arrays.copyOf(objArrCopyOf, objArrCopyOf.length));
        j.e(str2, "java.lang.String.format(locale, format, *args)");
        return str2;
    }

    public static final boolean r(String[] strArr, String[] strArr2, Comparator comparator) {
        j.f(strArr, "$this$hasIntersection");
        j.f(comparator, "comparator");
        if (strArr.length != 0 && strArr2 != null && strArr2.length != 0) {
            for (String str : strArr) {
                for (String str2 : strArr2) {
                    if (comparator.compare(str, str2) == 0) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public static final long s(B2.D d3) {
        j.f(d3, "$this$headersContentLength");
        String strA = d3.e0().a("Content-Length");
        if (strA != null) {
            return T(strA, -1L);
        }
        return -1L;
    }

    public static final List t(Object... objArr) {
        j.f(objArr, "elements");
        Object[] objArr2 = (Object[]) objArr.clone();
        List listUnmodifiableList = Collections.unmodifiableList(AbstractC0586n.i(Arrays.copyOf(objArr2, objArr2.length)));
        j.e(listUnmodifiableList, "Collections.unmodifiable…istOf(*elements.clone()))");
        return listUnmodifiableList;
    }

    public static final int u(String[] strArr, String str, Comparator comparator) {
        j.f(strArr, "$this$indexOf");
        j.f(str, "value");
        j.f(comparator, "comparator");
        int length = strArr.length;
        for (int i3 = 0; i3 < length; i3++) {
            if (comparator.compare(strArr[i3], str) == 0) {
                return i3;
            }
        }
        return -1;
    }

    public static final int v(String str) {
        j.f(str, "$this$indexOfControlOrNonAscii");
        int length = str.length();
        for (int i3 = 0; i3 < length; i3++) {
            char cCharAt = str.charAt(i3);
            if (j.g(cCharAt, 31) <= 0 || j.g(cCharAt, 127) >= 0) {
                return i3;
            }
        }
        return -1;
    }

    public static final int w(String str, int i3, int i4) {
        j.f(str, "$this$indexOfFirstNonAsciiWhitespace");
        while (i3 < i4) {
            char cCharAt = str.charAt(i3);
            if (cCharAt != '\t' && cCharAt != '\n' && cCharAt != '\f' && cCharAt != '\r' && cCharAt != ' ') {
                return i3;
            }
            i3++;
        }
        return i4;
    }

    public static /* synthetic */ int x(String str, int i3, int i4, int i5, Object obj) {
        if ((i5 & 1) != 0) {
            i3 = 0;
        }
        if ((i5 & 2) != 0) {
            i4 = str.length();
        }
        return w(str, i3, i4);
    }

    public static final int y(String str, int i3, int i4) {
        j.f(str, "$this$indexOfLastNonAsciiWhitespace");
        int i5 = i4 - 1;
        if (i5 >= i3) {
            while (true) {
                char cCharAt = str.charAt(i5);
                if (cCharAt != '\t' && cCharAt != '\n' && cCharAt != '\f' && cCharAt != '\r' && cCharAt != ' ') {
                    return i5 + 1;
                }
                if (i5 == i3) {
                    break;
                }
                i5--;
            }
        }
        return i3;
    }

    public static /* synthetic */ int z(String str, int i3, int i4, int i5, Object obj) {
        if ((i5 & 1) != 0) {
            i3 = 0;
        }
        if ((i5 & 2) != 0) {
            i4 = str.length();
        }
        return y(str, i3, i4);
    }
}
