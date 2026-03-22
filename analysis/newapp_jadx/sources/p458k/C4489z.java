package p458k;

import androidx.core.app.NotificationCompat;
import com.alibaba.fastjson.asm.Opcodes;
import com.google.android.material.badge.BadgeDrawable;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.TypeCastException;
import kotlin.jvm.JvmName;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.Regex;
import kotlin.text.StringsKt__StringsKt;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.p459p0.C4401c;
import p474l.C4744f;

/* renamed from: k.z */
/* loaded from: classes3.dex */
public final class C4489z {

    /* renamed from: c */
    public final boolean f12045c;

    /* renamed from: d */
    @NotNull
    public final String f12046d;

    /* renamed from: e */
    @NotNull
    public final String f12047e;

    /* renamed from: f */
    @NotNull
    public final String f12048f;

    /* renamed from: g */
    @NotNull
    public final String f12049g;

    /* renamed from: h */
    public final int f12050h;

    /* renamed from: i */
    @NotNull
    public final List<String> f12051i;

    /* renamed from: j */
    public final List<String> f12052j;

    /* renamed from: k */
    @Nullable
    public final String f12053k;

    /* renamed from: l */
    public final String f12054l;

    /* renamed from: b */
    public static final b f12044b = new b(null);

    /* renamed from: a */
    public static final char[] f12043a = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    /* renamed from: k.z$a */
    public static final class a {

        /* renamed from: a */
        public static final C5136a f12055a = new C5136a(null);

        /* renamed from: b */
        @Nullable
        public String f12056b;

        /* renamed from: e */
        @Nullable
        public String f12059e;

        /* renamed from: g */
        @NotNull
        public final List<String> f12061g;

        /* renamed from: h */
        @Nullable
        public List<String> f12062h;

        /* renamed from: i */
        @Nullable
        public String f12063i;

        /* renamed from: c */
        @NotNull
        public String f12057c = "";

        /* renamed from: d */
        @NotNull
        public String f12058d = "";

        /* renamed from: f */
        public int f12060f = -1;

        /* renamed from: k.z$a$a, reason: collision with other inner class name */
        public static final class C5136a {
            public C5136a(DefaultConstructorMarker defaultConstructorMarker) {
            }
        }

        public a() {
            ArrayList arrayList = new ArrayList();
            this.f12061g = arrayList;
            arrayList.add("");
        }

        @NotNull
        /* renamed from: a */
        public final C4489z m5299a() {
            String str = this.f12056b;
            if (str == null) {
                throw new IllegalStateException("scheme == null");
            }
            b bVar = C4489z.f12044b;
            String m5304e = b.m5304e(bVar, this.f12057c, 0, 0, false, 7);
            String m5304e2 = b.m5304e(bVar, this.f12058d, 0, 0, false, 7);
            String str2 = this.f12059e;
            if (str2 == null) {
                throw new IllegalStateException("host == null");
            }
            int m5300b = m5300b();
            List<String> m5307d = bVar.m5307d(this.f12061g, false);
            if (m5307d == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.collections.List<kotlin.String>");
            }
            List<String> list = this.f12062h;
            List<String> m5307d2 = list != null ? bVar.m5307d(list, true) : null;
            String str3 = this.f12063i;
            return new C4489z(str, m5304e, m5304e2, str2, m5300b, m5307d, m5307d2, str3 != null ? b.m5304e(bVar, str3, 0, 0, false, 7) : null, toString());
        }

        /* renamed from: b */
        public final int m5300b() {
            int i2 = this.f12060f;
            if (i2 != -1) {
                return i2;
            }
            String scheme = this.f12056b;
            if (scheme == null) {
                Intrinsics.throwNpe();
            }
            Intrinsics.checkParameterIsNotNull(scheme, "scheme");
            int hashCode = scheme.hashCode();
            if (hashCode != 3213448) {
                if (hashCode == 99617003 && scheme.equals("https")) {
                    return 443;
                }
            } else if (scheme.equals("http")) {
                return 80;
            }
            return -1;
        }

        @NotNull
        /* renamed from: c */
        public final a m5301c(@Nullable String str) {
            List<String> list;
            if (str != null) {
                b bVar = C4489z.f12044b;
                String m5303a = b.m5303a(bVar, str, 0, 0, " \"'<>#", true, false, true, false, null, 211);
                if (m5303a != null) {
                    list = bVar.m5308f(m5303a);
                    this.f12062h = list;
                    return this;
                }
            }
            list = null;
            this.f12062h = list;
            return this;
        }

        /* JADX WARN: Code restructure failed: missing block: B:28:0x006e, code lost:
        
            if (r15 == ':') goto L40;
         */
        /* JADX WARN: Multi-variable type inference failed */
        /* JADX WARN: Removed duplicated region for block: B:185:0x026b  */
        /* JADX WARN: Removed duplicated region for block: B:187:0x0270  */
        /* JADX WARN: Removed duplicated region for block: B:196:0x0274  */
        /* JADX WARN: Removed duplicated region for block: B:198:0x026d  */
        /* JADX WARN: Type inference failed for: r14v1 */
        /* JADX WARN: Type inference failed for: r14v13 */
        /* JADX WARN: Type inference failed for: r14v2 */
        /* JADX WARN: Type inference failed for: r14v3, types: [boolean] */
        /* JADX WARN: Type inference failed for: r14v5 */
        /* JADX WARN: Type inference failed for: r14v6 */
        /* JADX WARN: Type inference failed for: r14v7 */
        /* JADX WARN: Type inference failed for: r2v50 */
        /* JADX WARN: Type inference failed for: r2v64 */
        /* JADX WARN: Unreachable blocks removed: 1, instructions: 2 */
        @org.jetbrains.annotations.NotNull
        /* renamed from: d */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final p458k.C4489z.a m5302d(@org.jetbrains.annotations.Nullable p458k.C4489z r30, @org.jetbrains.annotations.NotNull java.lang.String r31) {
            /*
                Method dump skipped, instructions count: 1189
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p458k.C4489z.a.m5302d(k.z, java.lang.String):k.z$a");
        }

        /* JADX WARN: Code restructure failed: missing block: B:12:0x0033, code lost:
        
            if ((r9.f12058d.length() > 0) != false) goto L17;
         */
        /* JADX WARN: Code restructure failed: missing block: B:65:0x00b8, code lost:
        
            if (r1 != r5) goto L52;
         */
        @org.jetbrains.annotations.NotNull
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public java.lang.String toString() {
            /*
                Method dump skipped, instructions count: 345
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p458k.C4489z.a.toString():java.lang.String");
        }
    }

    /* renamed from: k.z$b */
    public static final class b {
        public b(DefaultConstructorMarker defaultConstructorMarker) {
        }

        /* renamed from: a */
        public static String m5303a(b bVar, String string, int i2, int i3, String encodeSet, boolean z, boolean z2, boolean z3, boolean z4, Charset charset, int i4) {
            String str;
            boolean z5;
            String str2;
            int i5 = (i4 & 1) != 0 ? 0 : i2;
            int length = (i4 & 2) != 0 ? string.length() : i3;
            boolean z6 = (i4 & 8) != 0 ? false : z;
            boolean z7 = (i4 & 16) != 0 ? false : z2;
            boolean z8 = (i4 & 32) != 0 ? false : z3;
            boolean z9 = (i4 & 64) != 0 ? false : z4;
            Charset charset2 = (i4 & 128) != 0 ? null : charset;
            Objects.requireNonNull(bVar);
            Intrinsics.checkParameterIsNotNull(string, "$this$canonicalize");
            Intrinsics.checkParameterIsNotNull(encodeSet, "encodeSet");
            int i6 = i5;
            while (i6 < length) {
                int codePointAt = string.codePointAt(i6);
                int i7 = 2;
                if (codePointAt < 32 || codePointAt == 127 || (codePointAt >= 128 && !z9)) {
                    str = "(this as java.lang.Strin…ing(startIndex, endIndex)";
                } else {
                    str = "(this as java.lang.Strin…ing(startIndex, endIndex)";
                    if (!StringsKt__StringsKt.contains$default((CharSequence) encodeSet, (char) codePointAt, false, 2, (Object) null) && ((codePointAt != 37 || (z6 && (!z7 || bVar.m5306c(string, i6, length)))) && (codePointAt != 43 || !z8))) {
                        i6 += Character.charCount(codePointAt);
                    }
                }
                C4744f c4744f = new C4744f();
                c4744f.m5382g0(string, i5, i6);
                C4744f c4744f2 = null;
                while (i6 < length) {
                    int codePointAt2 = string.codePointAt(i6);
                    if (!z6 || (codePointAt2 != 9 && codePointAt2 != 10 && codePointAt2 != 12 && codePointAt2 != 13)) {
                        if (codePointAt2 == 43 && z8) {
                            c4744f.m5381f0(z6 ? BadgeDrawable.DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX : "%2B");
                        } else {
                            if (codePointAt2 < 32 || codePointAt2 == 127 || (codePointAt2 >= 128 && !z9)) {
                                z5 = z8;
                            } else {
                                z5 = z8;
                                if (!StringsKt__StringsKt.contains$default((CharSequence) encodeSet, (char) codePointAt2, false, i7, (Object) null) && (codePointAt2 != 37 || (z6 && (!z7 || bVar.m5306c(string, i6, length))))) {
                                    c4744f.m5384h0(codePointAt2);
                                    str2 = str;
                                    i6 += Character.charCount(codePointAt2);
                                    i7 = 2;
                                    z8 = z5;
                                    str = str2;
                                }
                            }
                            if (c4744f2 == null) {
                                c4744f2 = new C4744f();
                            }
                            if (charset2 == null || Intrinsics.areEqual(charset2, StandardCharsets.UTF_8)) {
                                str2 = str;
                                c4744f2.m5384h0(codePointAt2);
                            } else {
                                int charCount = Character.charCount(codePointAt2) + i6;
                                Intrinsics.checkNotNullParameter(string, "string");
                                Intrinsics.checkNotNullParameter(charset2, "charset");
                                if (!(i6 >= 0)) {
                                    throw new IllegalArgumentException(C1499a.m626l("beginIndex < 0: ", i6).toString());
                                }
                                if (!(charCount >= i6)) {
                                    throw new IllegalArgumentException(C1499a.m629o("endIndex < beginIndex: ", charCount, " < ", i6).toString());
                                }
                                if (!(charCount <= string.length())) {
                                    StringBuilder m588J = C1499a.m588J("endIndex > string.length: ", charCount, " > ");
                                    m588J.append(string.length());
                                    throw new IllegalArgumentException(m588J.toString().toString());
                                }
                                if (Intrinsics.areEqual(charset2, Charsets.UTF_8)) {
                                    c4744f2.m5382g0(string, i6, charCount);
                                    str2 = str;
                                } else {
                                    String substring = string.substring(i6, charCount);
                                    str2 = str;
                                    Intrinsics.checkNotNullExpressionValue(substring, str2);
                                    Objects.requireNonNull(substring, "null cannot be cast to non-null type java.lang.String");
                                    byte[] bytes = substring.getBytes(charset2);
                                    Intrinsics.checkNotNullExpressionValue(bytes, "(this as java.lang.String).getBytes(charset)");
                                    c4744f2.m5372Z(bytes, 0, bytes.length);
                                }
                            }
                            while (!c4744f2.mo5387m()) {
                                int readByte = c4744f2.readByte() & 255;
                                c4744f.m5374a0(37);
                                char[] cArr = C4489z.f12043a;
                                c4744f.m5374a0(cArr[(readByte >> 4) & 15]);
                                c4744f.m5374a0(cArr[readByte & 15]);
                            }
                            i6 += Character.charCount(codePointAt2);
                            i7 = 2;
                            z8 = z5;
                            str = str2;
                        }
                    }
                    z5 = z8;
                    str2 = str;
                    i6 += Character.charCount(codePointAt2);
                    i7 = 2;
                    z8 = z5;
                    str = str2;
                }
                return c4744f.m5365S();
            }
            String substring2 = string.substring(i5, length);
            Intrinsics.checkExpressionValueIsNotNull(substring2, "(this as java.lang.Strin…ing(startIndex, endIndex)");
            return substring2;
        }

        /* renamed from: e */
        public static String m5304e(b bVar, String percentDecode, int i2, int i3, boolean z, int i4) {
            int i5;
            if ((i4 & 1) != 0) {
                i2 = 0;
            }
            if ((i4 & 2) != 0) {
                i3 = percentDecode.length();
            }
            if ((i4 & 4) != 0) {
                z = false;
            }
            Intrinsics.checkParameterIsNotNull(percentDecode, "$this$percentDecode");
            int i6 = i2;
            while (i6 < i3) {
                char charAt = percentDecode.charAt(i6);
                if (charAt == '%' || (charAt == '+' && z)) {
                    C4744f c4744f = new C4744f();
                    c4744f.m5382g0(percentDecode, i2, i6);
                    while (i6 < i3) {
                        int codePointAt = percentDecode.codePointAt(i6);
                        if (codePointAt != 37 || (i5 = i6 + 2) >= i3) {
                            if (codePointAt == 43 && z) {
                                c4744f.m5374a0(32);
                                i6++;
                            }
                            c4744f.m5384h0(codePointAt);
                            i6 += Character.charCount(codePointAt);
                        } else {
                            int m5032q = C4401c.m5032q(percentDecode.charAt(i6 + 1));
                            int m5032q2 = C4401c.m5032q(percentDecode.charAt(i5));
                            if (m5032q != -1 && m5032q2 != -1) {
                                c4744f.m5374a0((m5032q << 4) + m5032q2);
                                i6 = Character.charCount(codePointAt) + i5;
                            }
                            c4744f.m5384h0(codePointAt);
                            i6 += Character.charCount(codePointAt);
                        }
                    }
                    return c4744f.m5365S();
                }
                i6++;
            }
            String substring = percentDecode.substring(i2, i3);
            Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
            return substring;
        }

        @JvmStatic
        /* renamed from: b */
        public final int m5305b(@NotNull String scheme) {
            Intrinsics.checkParameterIsNotNull(scheme, "scheme");
            int hashCode = scheme.hashCode();
            if (hashCode != 3213448) {
                if (hashCode == 99617003 && scheme.equals("https")) {
                    return 443;
                }
            } else if (scheme.equals("http")) {
                return 80;
            }
            return -1;
        }

        /* renamed from: c */
        public final boolean m5306c(@NotNull String str, int i2, int i3) {
            int i4 = i2 + 2;
            return i4 < i3 && str.charAt(i2) == '%' && C4401c.m5032q(str.charAt(i2 + 1)) != -1 && C4401c.m5032q(str.charAt(i4)) != -1;
        }

        /* renamed from: d */
        public final List<String> m5307d(@NotNull List<String> list, boolean z) {
            ArrayList arrayList = new ArrayList(list.size());
            Iterator<String> it = list.iterator();
            while (it.hasNext()) {
                String next = it.next();
                arrayList.add(next != null ? m5304e(this, next, 0, 0, z, 3) : null);
            }
            List<String> unmodifiableList = Collections.unmodifiableList(arrayList);
            Intrinsics.checkExpressionValueIsNotNull(unmodifiableList, "Collections.unmodifiableList(result)");
            return unmodifiableList;
        }

        @NotNull
        /* renamed from: f */
        public final List<String> m5308f(@NotNull String toQueryNamesAndValues) {
            Intrinsics.checkParameterIsNotNull(toQueryNamesAndValues, "$this$toQueryNamesAndValues");
            ArrayList arrayList = new ArrayList();
            int i2 = 0;
            while (i2 <= toQueryNamesAndValues.length()) {
                int indexOf$default = StringsKt__StringsKt.indexOf$default((CharSequence) toQueryNamesAndValues, Typography.amp, i2, false, 4, (Object) null);
                if (indexOf$default == -1) {
                    indexOf$default = toQueryNamesAndValues.length();
                }
                int i3 = indexOf$default;
                int indexOf$default2 = StringsKt__StringsKt.indexOf$default((CharSequence) toQueryNamesAndValues, '=', i2, false, 4, (Object) null);
                if (indexOf$default2 == -1 || indexOf$default2 > i3) {
                    String substring = toQueryNamesAndValues.substring(i2, i3);
                    Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                    arrayList.add(substring);
                    arrayList.add(null);
                } else {
                    String substring2 = toQueryNamesAndValues.substring(i2, indexOf$default2);
                    Intrinsics.checkExpressionValueIsNotNull(substring2, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                    arrayList.add(substring2);
                    String substring3 = toQueryNamesAndValues.substring(indexOf$default2 + 1, i3);
                    Intrinsics.checkExpressionValueIsNotNull(substring3, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                    arrayList.add(substring3);
                }
                i2 = i3 + 1;
            }
            return arrayList;
        }
    }

    public C4489z(@NotNull String scheme, @NotNull String username, @NotNull String password, @NotNull String host, int i2, @NotNull List<String> pathSegments, @Nullable List<String> list, @Nullable String str, @NotNull String url) {
        Intrinsics.checkParameterIsNotNull(scheme, "scheme");
        Intrinsics.checkParameterIsNotNull(username, "username");
        Intrinsics.checkParameterIsNotNull(password, "password");
        Intrinsics.checkParameterIsNotNull(host, "host");
        Intrinsics.checkParameterIsNotNull(pathSegments, "pathSegments");
        Intrinsics.checkParameterIsNotNull(url, "url");
        this.f12046d = scheme;
        this.f12047e = username;
        this.f12048f = password;
        this.f12049g = host;
        this.f12050h = i2;
        this.f12051i = pathSegments;
        this.f12052j = list;
        this.f12053k = str;
        this.f12054l = url;
        this.f12045c = Intrinsics.areEqual(scheme, "https");
    }

    @JvmName(name = "encodedPassword")
    @NotNull
    /* renamed from: a */
    public final String m5291a() {
        if (this.f12048f.length() == 0) {
            return "";
        }
        int indexOf$default = StringsKt__StringsKt.indexOf$default((CharSequence) this.f12054l, ':', this.f12046d.length() + 3, false, 4, (Object) null) + 1;
        int indexOf$default2 = StringsKt__StringsKt.indexOf$default((CharSequence) this.f12054l, '@', 0, false, 6, (Object) null);
        String str = this.f12054l;
        if (str == null) {
            throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
        }
        String substring = str.substring(indexOf$default, indexOf$default2);
        Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        return substring;
    }

    @JvmName(name = "encodedPath")
    @NotNull
    /* renamed from: b */
    public final String m5292b() {
        int indexOf$default = StringsKt__StringsKt.indexOf$default((CharSequence) this.f12054l, '/', this.f12046d.length() + 3, false, 4, (Object) null);
        String str = this.f12054l;
        int m5022g = C4401c.m5022g(str, "?#", indexOf$default, str.length());
        String str2 = this.f12054l;
        if (str2 == null) {
            throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
        }
        String substring = str2.substring(indexOf$default, m5022g);
        Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        return substring;
    }

    @JvmName(name = "encodedPathSegments")
    @NotNull
    /* renamed from: c */
    public final List<String> m5293c() {
        int indexOf$default = StringsKt__StringsKt.indexOf$default((CharSequence) this.f12054l, '/', this.f12046d.length() + 3, false, 4, (Object) null);
        String str = this.f12054l;
        int m5022g = C4401c.m5022g(str, "?#", indexOf$default, str.length());
        ArrayList arrayList = new ArrayList();
        while (indexOf$default < m5022g) {
            int i2 = indexOf$default + 1;
            int m5021f = C4401c.m5021f(this.f12054l, '/', i2, m5022g);
            String str2 = this.f12054l;
            if (str2 == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
            }
            String substring = str2.substring(i2, m5021f);
            Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
            arrayList.add(substring);
            indexOf$default = m5021f;
        }
        return arrayList;
    }

    @JvmName(name = "encodedQuery")
    @Nullable
    /* renamed from: d */
    public final String m5294d() {
        if (this.f12052j == null) {
            return null;
        }
        int indexOf$default = StringsKt__StringsKt.indexOf$default((CharSequence) this.f12054l, '?', 0, false, 6, (Object) null) + 1;
        String str = this.f12054l;
        int m5021f = C4401c.m5021f(str, '#', indexOf$default, str.length());
        String str2 = this.f12054l;
        if (str2 == null) {
            throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
        }
        String substring = str2.substring(indexOf$default, m5021f);
        Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        return substring;
    }

    @JvmName(name = "encodedUsername")
    @NotNull
    /* renamed from: e */
    public final String m5295e() {
        if (this.f12047e.length() == 0) {
            return "";
        }
        int length = this.f12046d.length() + 3;
        String str = this.f12054l;
        int m5022g = C4401c.m5022g(str, ":@", length, str.length());
        String str2 = this.f12054l;
        if (str2 == null) {
            throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
        }
        String substring = str2.substring(length, m5022g);
        Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        return substring;
    }

    public boolean equals(@Nullable Object obj) {
        return (obj instanceof C4489z) && Intrinsics.areEqual(((C4489z) obj).f12054l, this.f12054l);
    }

    @Nullable
    /* renamed from: f */
    public final a m5296f(@NotNull String link) {
        Intrinsics.checkParameterIsNotNull(link, "link");
        try {
            a aVar = new a();
            aVar.m5302d(this, link);
            return aVar;
        } catch (IllegalArgumentException unused) {
            return null;
        }
    }

    @NotNull
    /* renamed from: g */
    public final String m5297g() {
        a m5296f = m5296f("/...");
        if (m5296f == null) {
            Intrinsics.throwNpe();
        }
        Objects.requireNonNull(m5296f);
        Intrinsics.checkParameterIsNotNull("", "username");
        b bVar = f12044b;
        m5296f.f12057c = b.m5303a(bVar, "", 0, 0, " \"':;<=>@[]^`{}|/\\?#", false, false, false, false, null, 251);
        Intrinsics.checkParameterIsNotNull("", "password");
        m5296f.f12058d = b.m5303a(bVar, "", 0, 0, " \"':;<=>@[]^`{}|/\\?#", false, false, false, false, null, 251);
        return m5296f.m5299a().f12054l;
    }

    @JvmName(name = NotificationCompat.MessagingStyle.Message.KEY_DATA_URI)
    @NotNull
    /* renamed from: h */
    public final URI m5298h() {
        int i2;
        String substring;
        a aVar = new a();
        aVar.f12056b = this.f12046d;
        String m5295e = m5295e();
        Intrinsics.checkParameterIsNotNull(m5295e, "<set-?>");
        aVar.f12057c = m5295e;
        String m5291a = m5291a();
        Intrinsics.checkParameterIsNotNull(m5291a, "<set-?>");
        aVar.f12058d = m5291a;
        aVar.f12059e = this.f12049g;
        int i3 = this.f12050h;
        String scheme = this.f12046d;
        Intrinsics.checkParameterIsNotNull(scheme, "scheme");
        int hashCode = scheme.hashCode();
        if (hashCode != 3213448) {
            if (hashCode == 99617003 && scheme.equals("https")) {
                i2 = 443;
            }
            i2 = -1;
        } else {
            if (scheme.equals("http")) {
                i2 = 80;
            }
            i2 = -1;
        }
        aVar.f12060f = i3 != i2 ? this.f12050h : -1;
        aVar.f12061g.clear();
        aVar.f12061g.addAll(m5293c());
        aVar.m5301c(m5294d());
        if (this.f12053k == null) {
            substring = null;
        } else {
            int indexOf$default = StringsKt__StringsKt.indexOf$default((CharSequence) this.f12054l, '#', 0, false, 6, (Object) null) + 1;
            String str = this.f12054l;
            if (str == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
            }
            substring = str.substring(indexOf$default);
            Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.String).substring(startIndex)");
        }
        aVar.f12063i = substring;
        String str2 = aVar.f12059e;
        aVar.f12059e = str2 != null ? new Regex("[\"<>^`{|}]").replace(str2, "") : null;
        int size = aVar.f12061g.size();
        for (int i4 = 0; i4 < size; i4++) {
            List<String> list = aVar.f12061g;
            list.set(i4, b.m5303a(f12044b, list.get(i4), 0, 0, "[]", true, true, false, false, null, 227));
        }
        List<String> list2 = aVar.f12062h;
        if (list2 != null) {
            int size2 = list2.size();
            for (int i5 = 0; i5 < size2; i5++) {
                String str3 = list2.get(i5);
                list2.set(i5, str3 != null ? b.m5303a(f12044b, str3, 0, 0, "\\^`{|}", true, true, true, false, null, 195) : null);
            }
        }
        String str4 = aVar.f12063i;
        aVar.f12063i = str4 != null ? b.m5303a(f12044b, str4, 0, 0, " \"#<>\\^`{|}", true, true, false, true, null, Opcodes.IF_ICMPGT) : null;
        String aVar2 = aVar.toString();
        try {
            return new URI(aVar2);
        } catch (URISyntaxException e2) {
            try {
                URI create = URI.create(new Regex("[\\u0000-\\u001F\\u007F-\\u009F\\p{javaWhitespace}]").replace(aVar2, ""));
                Intrinsics.checkExpressionValueIsNotNull(create, "URI.create(stripped)");
                return create;
            } catch (Exception unused) {
                throw new RuntimeException(e2);
            }
        }
    }

    public int hashCode() {
        return this.f12054l.hashCode();
    }

    @NotNull
    public String toString() {
        return this.f12054l;
    }
}
