package p458k;

import java.nio.charset.Charset;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.TypeCastException;
import kotlin.jvm.JvmName;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: k.b0 */
/* loaded from: classes3.dex */
public final class C4371b0 {

    /* renamed from: a */
    public static final Pattern f11307a = Pattern.compile("([a-zA-Z0-9-!#$%&'*+.^_`{|}~]+)/([a-zA-Z0-9-!#$%&'*+.^_`{|}~]+)");

    /* renamed from: b */
    public static final Pattern f11308b = Pattern.compile(";\\s*(?:([a-zA-Z0-9-!#$%&'*+.^_`{|}~]+)=(?:([a-zA-Z0-9-!#$%&'*+.^_`{|}~]+)|\"([^\"]*)\"))?");

    /* renamed from: c */
    public static final a f11309c = null;

    /* renamed from: d */
    public final String f11310d;

    /* renamed from: e */
    @NotNull
    public final String f11311e;

    /* renamed from: f */
    public final String f11312f;

    /* renamed from: k.b0$a */
    public static final class a {
        @JvmStatic
        @JvmName(name = "get")
        @NotNull
        /* renamed from: a */
        public static final C4371b0 m4945a(@NotNull String toMediaType) {
            Intrinsics.checkParameterIsNotNull(toMediaType, "$this$toMediaType");
            Matcher matcher = C4371b0.f11307a.matcher(toMediaType);
            if (!matcher.lookingAt()) {
                throw new IllegalArgumentException(("No subtype found for: \"" + toMediaType + Typography.quote).toString());
            }
            String group = matcher.group(1);
            Intrinsics.checkExpressionValueIsNotNull(group, "typeSubtype.group(1)");
            Locale locale = Locale.US;
            Intrinsics.checkExpressionValueIsNotNull(locale, "Locale.US");
            if (group == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
            }
            String lowerCase = group.toLowerCase(locale);
            Intrinsics.checkExpressionValueIsNotNull(lowerCase, "(this as java.lang.String).toLowerCase(locale)");
            String group2 = matcher.group(2);
            Intrinsics.checkExpressionValueIsNotNull(group2, "typeSubtype.group(2)");
            Intrinsics.checkExpressionValueIsNotNull(locale, "Locale.US");
            if (group2 == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
            }
            String lowerCase2 = group2.toLowerCase(locale);
            Intrinsics.checkExpressionValueIsNotNull(lowerCase2, "(this as java.lang.String).toLowerCase(locale)");
            Matcher matcher2 = C4371b0.f11308b.matcher(toMediaType);
            int end = matcher.end();
            String str = null;
            while (end < toMediaType.length()) {
                matcher2.region(end, toMediaType.length());
                if (!matcher2.lookingAt()) {
                    StringBuilder m586H = C1499a.m586H("Parameter is not formatted correctly: \"");
                    String substring = toMediaType.substring(end);
                    Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.String).substring(startIndex)");
                    m586H.append(substring);
                    m586H.append("\" for: \"");
                    m586H.append(toMediaType);
                    m586H.append(Typography.quote);
                    throw new IllegalArgumentException(m586H.toString().toString());
                }
                String group3 = matcher2.group(1);
                if (group3 == null || !StringsKt__StringsJVMKt.equals(group3, "charset", true)) {
                    end = matcher2.end();
                } else {
                    String group4 = matcher2.group(2);
                    if (group4 == null) {
                        group4 = matcher2.group(3);
                        Intrinsics.checkExpressionValueIsNotNull(group4, "parameter.group(3)");
                    } else if (StringsKt__StringsJVMKt.startsWith$default(group4, "'", false, 2, null) && StringsKt__StringsJVMKt.endsWith$default(group4, "'", false, 2, null) && group4.length() > 2) {
                        group4 = group4.substring(1, group4.length() - 1);
                        Intrinsics.checkExpressionValueIsNotNull(group4, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                    }
                    if (!(str == null || StringsKt__StringsJVMKt.equals(group4, str, true))) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("Multiple charsets defined: \"");
                        sb.append(str);
                        sb.append("\" and: \"");
                        sb.append(group4);
                        sb.append("\" for: \"");
                        throw new IllegalArgumentException(C1499a.m581C(sb, toMediaType, Typography.quote).toString());
                    }
                    str = group4;
                    end = matcher2.end();
                }
            }
            return new C4371b0(toMediaType, lowerCase, lowerCase2, str, null);
        }

        @JvmStatic
        @JvmName(name = "parse")
        @Nullable
        /* renamed from: b */
        public static final C4371b0 m4946b(@NotNull String toMediaTypeOrNull) {
            Intrinsics.checkParameterIsNotNull(toMediaTypeOrNull, "$this$toMediaTypeOrNull");
            try {
                return m4945a(toMediaTypeOrNull);
            } catch (IllegalArgumentException unused) {
                return null;
            }
        }
    }

    public C4371b0(String str, String str2, String str3, String str4, DefaultConstructorMarker defaultConstructorMarker) {
        this.f11310d = str;
        this.f11311e = str2;
        this.f11312f = str4;
    }

    @JvmOverloads
    @Nullable
    /* renamed from: a */
    public final Charset m4944a(@Nullable Charset charset) {
        try {
            String str = this.f11312f;
            return str != null ? Charset.forName(str) : charset;
        } catch (IllegalArgumentException unused) {
            return charset;
        }
    }

    public boolean equals(@Nullable Object obj) {
        return (obj instanceof C4371b0) && Intrinsics.areEqual(((C4371b0) obj).f11310d, this.f11310d);
    }

    public int hashCode() {
        return this.f11310d.hashCode();
    }

    @NotNull
    public String toString() {
        return this.f11310d;
    }
}
