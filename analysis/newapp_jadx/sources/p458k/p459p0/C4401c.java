package p458k.p459p0;

import java.io.Closeable;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.StringCompanionObject;
import kotlin.text.Charsets;
import kotlin.text.Regex;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.AbstractC4393m0;
import p458k.C4389k0;
import p458k.C4488y;
import p458k.C4489z;
import p458k.p459p0.p465i.C4437c;
import p474l.C4747i;
import p474l.C4755q;
import p474l.InterfaceC4746h;
import p474l.InterfaceC4764z;

@JvmName(name = "Util")
/* renamed from: k.p0.c */
/* loaded from: classes3.dex */
public final class C4401c {

    /* renamed from: a */
    @JvmField
    @NotNull
    public static final byte[] f11556a;

    /* renamed from: b */
    @JvmField
    @NotNull
    public static final C4488y f11557b = C4488y.f12040c.m5290c(new String[0]);

    /* renamed from: c */
    @JvmField
    @NotNull
    public static final AbstractC4393m0 f11558c;

    /* renamed from: d */
    public static final C4755q f11559d;

    /* renamed from: e */
    @JvmField
    @NotNull
    public static final TimeZone f11560e;

    /* renamed from: f */
    public static final Regex f11561f;

    /* JADX WARN: Code restructure failed: missing block: B:39:0x0147, code lost:
    
        continue;
     */
    static {
        /*
            Method dump skipped, instructions count: 429
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.C4401c.<clinit>():void");
    }

    /* renamed from: a */
    public static final boolean m5016a(@NotNull C4489z canReuseConnectionFor, @NotNull C4489z other) {
        Intrinsics.checkParameterIsNotNull(canReuseConnectionFor, "$this$canReuseConnectionFor");
        Intrinsics.checkParameterIsNotNull(other, "other");
        return Intrinsics.areEqual(canReuseConnectionFor.f12049g, other.f12049g) && canReuseConnectionFor.f12050h == other.f12050h && Intrinsics.areEqual(canReuseConnectionFor.f12046d, other.f12046d);
    }

    /* renamed from: b */
    public static final int m5017b(@NotNull String name, long j2, @Nullable TimeUnit timeUnit) {
        Intrinsics.checkParameterIsNotNull(name, "name");
        if (!(j2 >= 0)) {
            throw new IllegalStateException(C1499a.m637w(name, " < 0").toString());
        }
        if (!(timeUnit != null)) {
            throw new IllegalStateException("unit == null".toString());
        }
        long millis = timeUnit.toMillis(j2);
        if (!(millis <= ((long) Integer.MAX_VALUE))) {
            throw new IllegalArgumentException(C1499a.m637w(name, " too large.").toString());
        }
        if (millis != 0 || j2 <= 0) {
            return (int) millis;
        }
        throw new IllegalArgumentException(C1499a.m637w(name, " too small.").toString());
    }

    /* renamed from: c */
    public static final void m5018c(long j2, long j3, long j4) {
        if ((j3 | j4) < 0 || j3 > j2 || j2 - j3 < j4) {
            throw new ArrayIndexOutOfBoundsException();
        }
    }

    /* renamed from: d */
    public static final void m5019d(@NotNull Closeable closeQuietly) {
        Intrinsics.checkParameterIsNotNull(closeQuietly, "$this$closeQuietly");
        try {
            closeQuietly.close();
        } catch (RuntimeException e2) {
            throw e2;
        } catch (Exception unused) {
        }
    }

    /* renamed from: e */
    public static final void m5020e(@NotNull Socket closeQuietly) {
        Intrinsics.checkParameterIsNotNull(closeQuietly, "$this$closeQuietly");
        try {
            closeQuietly.close();
        } catch (AssertionError e2) {
            throw e2;
        } catch (RuntimeException e3) {
            throw e3;
        } catch (Exception unused) {
        }
    }

    /* renamed from: f */
    public static final int m5021f(@NotNull String delimiterOffset, char c2, int i2, int i3) {
        Intrinsics.checkParameterIsNotNull(delimiterOffset, "$this$delimiterOffset");
        while (i2 < i3) {
            if (delimiterOffset.charAt(i2) == c2) {
                return i2;
            }
            i2++;
        }
        return i3;
    }

    /* renamed from: g */
    public static final int m5022g(@NotNull String delimiterOffset, @NotNull String delimiters, int i2, int i3) {
        Intrinsics.checkParameterIsNotNull(delimiterOffset, "$this$delimiterOffset");
        Intrinsics.checkParameterIsNotNull(delimiters, "delimiters");
        while (i2 < i3) {
            if (StringsKt__StringsKt.contains$default((CharSequence) delimiters, delimiterOffset.charAt(i2), false, 2, (Object) null)) {
                return i2;
            }
            i2++;
        }
        return i3;
    }

    /* renamed from: h */
    public static final boolean m5023h(@NotNull InterfaceC4764z discard, int i2, @NotNull TimeUnit timeUnit) {
        Intrinsics.checkParameterIsNotNull(discard, "$this$discard");
        Intrinsics.checkParameterIsNotNull(timeUnit, "timeUnit");
        try {
            return m5035t(discard, i2, timeUnit);
        } catch (IOException unused) {
            return false;
        }
    }

    @NotNull
    /* renamed from: i */
    public static final String m5024i(@NotNull String format, @NotNull Object... args) {
        Intrinsics.checkParameterIsNotNull(format, "format");
        Intrinsics.checkParameterIsNotNull(args, "args");
        StringCompanionObject stringCompanionObject = StringCompanionObject.INSTANCE;
        Locale locale = Locale.US;
        Intrinsics.checkExpressionValueIsNotNull(locale, "Locale.US");
        Object[] copyOf = Arrays.copyOf(args, args.length);
        String format2 = String.format(locale, format, Arrays.copyOf(copyOf, copyOf.length));
        Intrinsics.checkExpressionValueIsNotNull(format2, "java.lang.String.format(locale, format, *args)");
        return format2;
    }

    /* renamed from: j */
    public static final boolean m5025j(@NotNull String[] hasIntersection, @Nullable String[] strArr, @NotNull Comparator<? super String> comparator) {
        Intrinsics.checkParameterIsNotNull(hasIntersection, "$this$hasIntersection");
        Intrinsics.checkParameterIsNotNull(comparator, "comparator");
        if (!(hasIntersection.length == 0) && strArr != null) {
            if (!(strArr.length == 0)) {
                for (String str : hasIntersection) {
                    for (String str2 : strArr) {
                        if (comparator.compare(str, str2) == 0) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    /* renamed from: k */
    public static final long m5026k(@NotNull C4389k0 headersContentLength) {
        Intrinsics.checkParameterIsNotNull(headersContentLength, "$this$headersContentLength");
        String toLongOrDefault = headersContentLength.f11490j.m5277a("Content-Length");
        if (toLongOrDefault != null) {
            Intrinsics.checkParameterIsNotNull(toLongOrDefault, "$this$toLongOrDefault");
            try {
                return Long.parseLong(toLongOrDefault);
            } catch (NumberFormatException unused) {
            }
        }
        return -1L;
    }

    @SafeVarargs
    @NotNull
    /* renamed from: l */
    public static final <T> List<T> m5027l(@NotNull T... elements) {
        Intrinsics.checkParameterIsNotNull(elements, "elements");
        Object[] objArr = (Object[]) elements.clone();
        List<T> unmodifiableList = Collections.unmodifiableList(Arrays.asList(Arrays.copyOf(objArr, objArr.length)));
        Intrinsics.checkExpressionValueIsNotNull(unmodifiableList, "Collections.unmodifiable…sList(*elements.clone()))");
        return unmodifiableList;
    }

    /* renamed from: m */
    public static final int m5028m(@NotNull String indexOfControlOrNonAscii) {
        Intrinsics.checkParameterIsNotNull(indexOfControlOrNonAscii, "$this$indexOfControlOrNonAscii");
        int length = indexOfControlOrNonAscii.length();
        for (int i2 = 0; i2 < length; i2++) {
            char charAt = indexOfControlOrNonAscii.charAt(i2);
            if (charAt <= 31 || charAt >= 127) {
                return i2;
            }
        }
        return -1;
    }

    /* renamed from: n */
    public static final int m5029n(@NotNull String indexOfFirstNonAsciiWhitespace, int i2, int i3) {
        Intrinsics.checkParameterIsNotNull(indexOfFirstNonAsciiWhitespace, "$this$indexOfFirstNonAsciiWhitespace");
        while (i2 < i3) {
            char charAt = indexOfFirstNonAsciiWhitespace.charAt(i2);
            if (charAt != '\t' && charAt != '\n' && charAt != '\f' && charAt != '\r' && charAt != ' ') {
                return i2;
            }
            i2++;
        }
        return i3;
    }

    /* renamed from: o */
    public static final int m5030o(@NotNull String indexOfLastNonAsciiWhitespace, int i2, int i3) {
        Intrinsics.checkParameterIsNotNull(indexOfLastNonAsciiWhitespace, "$this$indexOfLastNonAsciiWhitespace");
        int i4 = i3 - 1;
        if (i4 >= i2) {
            while (true) {
                char charAt = indexOfLastNonAsciiWhitespace.charAt(i4);
                if (charAt != '\t' && charAt != '\n' && charAt != '\f' && charAt != '\r' && charAt != ' ') {
                    return i4 + 1;
                }
                if (i4 == i2) {
                    break;
                }
                i4--;
            }
        }
        return i2;
    }

    @NotNull
    /* renamed from: p */
    public static final String[] m5031p(@NotNull String[] intersect, @NotNull String[] other, @NotNull Comparator<? super String> comparator) {
        Intrinsics.checkParameterIsNotNull(intersect, "$this$intersect");
        Intrinsics.checkParameterIsNotNull(other, "other");
        Intrinsics.checkParameterIsNotNull(comparator, "comparator");
        ArrayList arrayList = new ArrayList();
        for (String str : intersect) {
            int length = other.length;
            int i2 = 0;
            while (true) {
                if (i2 >= length) {
                    break;
                }
                if (comparator.compare(str, other[i2]) == 0) {
                    arrayList.add(str);
                    break;
                }
                i2++;
            }
        }
        Object[] array = arrayList.toArray(new String[0]);
        if (array != null) {
            return (String[]) array;
        }
        throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
    }

    /* renamed from: q */
    public static final int m5032q(char c2) {
        if ('0' <= c2 && '9' >= c2) {
            return c2 - '0';
        }
        char c3 = 'a';
        if ('a' > c2 || 'f' < c2) {
            c3 = 'A';
            if ('A' > c2 || 'F' < c2) {
                return -1;
            }
        }
        return (c2 - c3) + 10;
    }

    @NotNull
    /* renamed from: r */
    public static final Charset m5033r(@NotNull InterfaceC4746h readBomAsCharset, @NotNull Charset charset) {
        Intrinsics.checkParameterIsNotNull(readBomAsCharset, "$this$readBomAsCharset");
        Intrinsics.checkParameterIsNotNull(charset, "default");
        int mo5366T = readBomAsCharset.mo5366T(f11559d);
        if (mo5366T == -1) {
            return charset;
        }
        if (mo5366T == 0) {
            Charset UTF_8 = StandardCharsets.UTF_8;
            Intrinsics.checkExpressionValueIsNotNull(UTF_8, "UTF_8");
            return UTF_8;
        }
        if (mo5366T == 1) {
            Charset UTF_16BE = StandardCharsets.UTF_16BE;
            Intrinsics.checkExpressionValueIsNotNull(UTF_16BE, "UTF_16BE");
            return UTF_16BE;
        }
        if (mo5366T == 2) {
            Charset UTF_16LE = StandardCharsets.UTF_16LE;
            Intrinsics.checkExpressionValueIsNotNull(UTF_16LE, "UTF_16LE");
            return UTF_16LE;
        }
        if (mo5366T == 3) {
            return Charsets.INSTANCE.UTF32_BE();
        }
        if (mo5366T == 4) {
            return Charsets.INSTANCE.UTF32_LE();
        }
        throw new AssertionError();
    }

    /* renamed from: s */
    public static final int m5034s(@NotNull InterfaceC4746h readMedium) {
        Intrinsics.checkParameterIsNotNull(readMedium, "$this$readMedium");
        return (readMedium.readByte() & 255) | ((readMedium.readByte() & 255) << 16) | ((readMedium.readByte() & 255) << 8);
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x0053, code lost:
    
        if (r5 == Long.MAX_VALUE) goto L14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0055, code lost:
    
        r11.mo5044c().mo5337a();
     */
    /* JADX WARN: Code restructure failed: missing block: B:14:0x0083, code lost:
    
        return r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x005d, code lost:
    
        r11.mo5044c().mo5340d(r0 + r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x0080, code lost:
    
        if (r5 != Long.MAX_VALUE) goto L15;
     */
    /* renamed from: t */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean m5035t(@org.jetbrains.annotations.NotNull p474l.InterfaceC4764z r11, int r12, @org.jetbrains.annotations.NotNull java.util.concurrent.TimeUnit r13) {
        /*
            java.lang.String r0 = "$this$skipAll"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r11, r0)
            java.lang.String r0 = "timeUnit"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r13, r0)
            long r0 = java.lang.System.nanoTime()
            l.a0 r2 = r11.mo5044c()
            boolean r2 = r2.mo5341e()
            r3 = 9223372036854775807(0x7fffffffffffffff, double:NaN)
            if (r2 == 0) goto L27
            l.a0 r2 = r11.mo5044c()
            long r5 = r2.mo5339c()
            long r5 = r5 - r0
            goto L28
        L27:
            r5 = r3
        L28:
            l.a0 r2 = r11.mo5044c()
            long r7 = (long) r12
            long r12 = r13.toNanos(r7)
            long r12 = java.lang.Math.min(r5, r12)
            long r12 = r12 + r0
            r2.mo5340d(r12)
            l.f r12 = new l.f     // Catch: java.lang.Throwable -> L66 java.io.InterruptedIOException -> L7c
            r12.<init>()     // Catch: java.lang.Throwable -> L66 java.io.InterruptedIOException -> L7c
        L3e:
            r7 = 8192(0x2000, double:4.0474E-320)
            long r7 = r11.mo4924J(r12, r7)     // Catch: java.lang.Throwable -> L66 java.io.InterruptedIOException -> L7c
            r9 = -1
            int r13 = (r7 > r9 ? 1 : (r7 == r9 ? 0 : -1))
            if (r13 == 0) goto L50
            long r7 = r12.f12133e     // Catch: java.lang.Throwable -> L66 java.io.InterruptedIOException -> L7c
            r12.skip(r7)     // Catch: java.lang.Throwable -> L66 java.io.InterruptedIOException -> L7c
            goto L3e
        L50:
            r12 = 1
            int r13 = (r5 > r3 ? 1 : (r5 == r3 ? 0 : -1))
            if (r13 != 0) goto L5d
        L55:
            l.a0 r11 = r11.mo5044c()
            r11.mo5337a()
            goto L83
        L5d:
            l.a0 r11 = r11.mo5044c()
            long r0 = r0 + r5
            r11.mo5340d(r0)
            goto L83
        L66:
            r12 = move-exception
            int r13 = (r5 > r3 ? 1 : (r5 == r3 ? 0 : -1))
            if (r13 != 0) goto L73
            l.a0 r11 = r11.mo5044c()
            r11.mo5337a()
            goto L7b
        L73:
            l.a0 r11 = r11.mo5044c()
            long r0 = r0 + r5
            r11.mo5340d(r0)
        L7b:
            throw r12
        L7c:
            r12 = 0
            int r13 = (r5 > r3 ? 1 : (r5 == r3 ? 0 : -1))
            if (r13 != 0) goto L5d
            goto L55
        L83:
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.C4401c.m5035t(l.z, int, java.util.concurrent.TimeUnit):boolean");
    }

    @NotNull
    /* renamed from: u */
    public static final C4488y m5036u(@NotNull List<C4437c> toHeaders) {
        Intrinsics.checkParameterIsNotNull(toHeaders, "$this$toHeaders");
        ArrayList arrayList = new ArrayList(20);
        for (C4437c c4437c : toHeaders) {
            C4747i c4747i = c4437c.f11790h;
            C4747i c4747i2 = c4437c.f11791i;
            String name = c4747i.m5407j();
            String value = c4747i2.m5407j();
            Intrinsics.checkParameterIsNotNull(name, "name");
            Intrinsics.checkParameterIsNotNull(value, "value");
            arrayList.add(name);
            arrayList.add(StringsKt__StringsKt.trim((CharSequence) value).toString());
        }
        Object[] array = arrayList.toArray(new String[0]);
        if (array != null) {
            return new C4488y((String[]) array, null);
        }
        throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
    }

    /* JADX WARN: Removed duplicated region for block: B:13:? A[RETURN, SYNTHETIC] */
    @org.jetbrains.annotations.NotNull
    /* renamed from: v */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.String m5037v(@org.jetbrains.annotations.NotNull p458k.C4489z r5, boolean r6) {
        /*
            java.lang.String r0 = "$this$toHostHeader"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r5, r0)
            java.lang.String r0 = r5.f12049g
            r1 = 0
            r2 = 2
            r3 = 0
            java.lang.String r4 = ":"
            boolean r0 = kotlin.text.StringsKt__StringsKt.contains$default(r0, r4, r1, r2, r3)
            if (r0 == 0) goto L21
            r0 = 91
            java.lang.StringBuilder r0 = p005b.p131d.p132a.p133a.C1499a.m584F(r0)
            java.lang.String r1 = r5.f12049g
            r2 = 93
            java.lang.String r0 = p005b.p131d.p132a.p133a.C1499a.m581C(r0, r1, r2)
            goto L23
        L21:
            java.lang.String r0 = r5.f12049g
        L23:
            if (r6 != 0) goto L56
            int r6 = r5.f12050h
            java.lang.String r1 = r5.f12046d
            java.lang.String r2 = "scheme"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r1, r2)
            int r2 = r1.hashCode()
            r3 = 3213448(0x310888, float:4.503E-39)
            if (r2 == r3) goto L48
            r3 = 99617003(0x5f008eb, float:2.2572767E-35)
            if (r2 == r3) goto L3d
            goto L53
        L3d:
            java.lang.String r2 = "https"
            boolean r1 = r1.equals(r2)
            if (r1 == 0) goto L53
            r1 = 443(0x1bb, float:6.21E-43)
            goto L54
        L48:
            java.lang.String r2 = "http"
            boolean r1 = r1.equals(r2)
            if (r1 == 0) goto L53
            r1 = 80
            goto L54
        L53:
            r1 = -1
        L54:
            if (r6 == r1) goto L6c
        L56:
            java.lang.StringBuilder r6 = new java.lang.StringBuilder
            r6.<init>()
            r6.append(r0)
            r0 = 58
            r6.append(r0)
            int r5 = r5.f12050h
            r6.append(r5)
            java.lang.String r0 = r6.toString()
        L6c:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.C4401c.m5037v(k.z, boolean):java.lang.String");
    }

    @NotNull
    /* renamed from: w */
    public static final <T> List<T> m5038w(@NotNull List<? extends T> toImmutableList) {
        Intrinsics.checkParameterIsNotNull(toImmutableList, "$this$toImmutableList");
        List<T> unmodifiableList = Collections.unmodifiableList(CollectionsKt___CollectionsKt.toMutableList((Collection) toImmutableList));
        Intrinsics.checkExpressionValueIsNotNull(unmodifiableList, "Collections.unmodifiableList(toMutableList())");
        return unmodifiableList;
    }

    /* renamed from: x */
    public static final int m5039x(@Nullable String str, int i2) {
        if (str != null) {
            try {
                long parseLong = Long.parseLong(str);
                if (parseLong > Integer.MAX_VALUE) {
                    return Integer.MAX_VALUE;
                }
                if (parseLong < 0) {
                    return 0;
                }
                return (int) parseLong;
            } catch (NumberFormatException unused) {
            }
        }
        return i2;
    }

    @NotNull
    /* renamed from: y */
    public static final String m5040y(@NotNull String trimSubstring, int i2, int i3) {
        Intrinsics.checkParameterIsNotNull(trimSubstring, "$this$trimSubstring");
        int m5029n = m5029n(trimSubstring, i2, i3);
        String substring = trimSubstring.substring(m5029n, m5030o(trimSubstring, m5029n, i3));
        Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        return substring;
    }
}
