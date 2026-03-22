package p458k;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.TypeCastException;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.p459p0.C4401c;
import p458k.p459p0.p463g.C4426c;

/* renamed from: k.p */
/* loaded from: classes3.dex */
public final class C4398p {

    /* renamed from: a */
    public static final Pattern f11539a = Pattern.compile("(\\d{2,4})[^\\d]*");

    /* renamed from: b */
    public static final Pattern f11540b = Pattern.compile("(?i)(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec).*");

    /* renamed from: c */
    public static final Pattern f11541c = Pattern.compile("(\\d{1,2})[^\\d]*");

    /* renamed from: d */
    public static final Pattern f11542d = Pattern.compile("(\\d{1,2}):(\\d{1,2}):(\\d{1,2})[^\\d]*");

    /* renamed from: e */
    public static final C4398p f11543e = null;

    /* renamed from: f */
    @NotNull
    public final String f11544f;

    /* renamed from: g */
    @NotNull
    public final String f11545g;

    /* renamed from: h */
    public final long f11546h;

    /* renamed from: i */
    @NotNull
    public final String f11547i;

    /* renamed from: j */
    @NotNull
    public final String f11548j;

    /* renamed from: k */
    public final boolean f11549k;

    /* renamed from: l */
    public final boolean f11550l;

    /* renamed from: m */
    public final boolean f11551m;

    /* renamed from: n */
    public final boolean f11552n;

    public C4398p(String str, String str2, long j2, String str3, String str4, boolean z, boolean z2, boolean z3, boolean z4, DefaultConstructorMarker defaultConstructorMarker) {
        this.f11544f = str;
        this.f11545g = str2;
        this.f11546h = j2;
        this.f11547i = str3;
        this.f11548j = str4;
        this.f11549k = z;
        this.f11550l = z2;
        this.f11551m = z3;
        this.f11552n = z4;
    }

    /* renamed from: a */
    public static final int m5013a(String str, int i2, int i3, boolean z) {
        while (i2 < i3) {
            char charAt = str.charAt(i2);
            if (((charAt < ' ' && charAt != '\t') || charAt >= 127 || ('0' <= charAt && '9' >= charAt) || (('a' <= charAt && 'z' >= charAt) || (('A' <= charAt && 'Z' >= charAt) || charAt == ':'))) == (!z)) {
                return i2;
            }
            i2++;
        }
        return i3;
    }

    /* renamed from: b */
    public static final long m5014b(String str, int i2, int i3) {
        int m5013a = m5013a(str, i2, i3, false);
        Matcher matcher = f11542d.matcher(str);
        int i4 = -1;
        int i5 = -1;
        int i6 = -1;
        int i7 = -1;
        int i8 = -1;
        int i9 = -1;
        while (m5013a < i3) {
            int m5013a2 = m5013a(str, m5013a + 1, i3, true);
            matcher.region(m5013a, m5013a2);
            if (i5 == -1 && matcher.usePattern(f11542d).matches()) {
                String group = matcher.group(1);
                Intrinsics.checkExpressionValueIsNotNull(group, "matcher.group(1)");
                int parseInt = Integer.parseInt(group);
                String group2 = matcher.group(2);
                Intrinsics.checkExpressionValueIsNotNull(group2, "matcher.group(2)");
                int parseInt2 = Integer.parseInt(group2);
                String group3 = matcher.group(3);
                Intrinsics.checkExpressionValueIsNotNull(group3, "matcher.group(3)");
                i9 = Integer.parseInt(group3);
                i8 = parseInt2;
                i5 = parseInt;
            } else if (i6 == -1 && matcher.usePattern(f11541c).matches()) {
                String group4 = matcher.group(1);
                Intrinsics.checkExpressionValueIsNotNull(group4, "matcher.group(1)");
                i6 = Integer.parseInt(group4);
            } else {
                if (i7 == -1) {
                    Pattern pattern = f11540b;
                    if (matcher.usePattern(pattern).matches()) {
                        String group5 = matcher.group(1);
                        Intrinsics.checkExpressionValueIsNotNull(group5, "matcher.group(1)");
                        Locale locale = Locale.US;
                        Intrinsics.checkExpressionValueIsNotNull(locale, "Locale.US");
                        if (group5 == null) {
                            throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
                        }
                        String lowerCase = group5.toLowerCase(locale);
                        Intrinsics.checkExpressionValueIsNotNull(lowerCase, "(this as java.lang.String).toLowerCase(locale)");
                        String pattern2 = pattern.pattern();
                        Intrinsics.checkExpressionValueIsNotNull(pattern2, "MONTH_PATTERN.pattern()");
                        i7 = StringsKt__StringsKt.indexOf$default((CharSequence) pattern2, lowerCase, 0, false, 6, (Object) null) / 4;
                    }
                }
                if (i4 == -1 && matcher.usePattern(f11539a).matches()) {
                    String group6 = matcher.group(1);
                    Intrinsics.checkExpressionValueIsNotNull(group6, "matcher.group(1)");
                    i4 = Integer.parseInt(group6);
                }
            }
            m5013a = m5013a(str, m5013a2 + 1, i3, false);
        }
        if (70 <= i4 && 99 >= i4) {
            i4 += 1900;
        }
        if (i4 >= 0 && 69 >= i4) {
            i4 += 2000;
        }
        if (!(i4 >= 1601)) {
            throw new IllegalArgumentException("Failed requirement.".toString());
        }
        if (!(i7 != -1)) {
            throw new IllegalArgumentException("Failed requirement.".toString());
        }
        if (!(1 <= i6 && 31 >= i6)) {
            throw new IllegalArgumentException("Failed requirement.".toString());
        }
        if (!(i5 >= 0 && 23 >= i5)) {
            throw new IllegalArgumentException("Failed requirement.".toString());
        }
        if (!(i8 >= 0 && 59 >= i8)) {
            throw new IllegalArgumentException("Failed requirement.".toString());
        }
        if (!(i9 >= 0 && 59 >= i9)) {
            throw new IllegalArgumentException("Failed requirement.".toString());
        }
        GregorianCalendar gregorianCalendar = new GregorianCalendar(C4401c.f11560e);
        gregorianCalendar.setLenient(false);
        gregorianCalendar.set(1, i4);
        gregorianCalendar.set(2, i7 - 1);
        gregorianCalendar.set(5, i6);
        gregorianCalendar.set(11, i5);
        gregorianCalendar.set(12, i8);
        gregorianCalendar.set(13, i9);
        gregorianCalendar.set(14, 0);
        return gregorianCalendar.getTimeInMillis();
    }

    public boolean equals(@Nullable Object obj) {
        if (obj instanceof C4398p) {
            C4398p c4398p = (C4398p) obj;
            if (Intrinsics.areEqual(c4398p.f11544f, this.f11544f) && Intrinsics.areEqual(c4398p.f11545g, this.f11545g) && c4398p.f11546h == this.f11546h && Intrinsics.areEqual(c4398p.f11547i, this.f11547i) && Intrinsics.areEqual(c4398p.f11548j, this.f11548j) && c4398p.f11549k == this.f11549k && c4398p.f11550l == this.f11550l && c4398p.f11551m == this.f11551m && c4398p.f11552n == this.f11552n) {
                return true;
            }
        }
        return false;
    }

    @IgnoreJRERequirement
    public int hashCode() {
        return C4396o.m5011a(this.f11552n) + ((C4396o.m5011a(this.f11551m) + ((C4396o.m5011a(this.f11550l) + ((C4396o.m5011a(this.f11549k) + C1499a.m598T(this.f11548j, C1499a.m598T(this.f11547i, (C4394n.m5009a(this.f11546h) + C1499a.m598T(this.f11545g, C1499a.m598T(this.f11544f, 527, 31), 31)) * 31, 31), 31)) * 31)) * 31)) * 31);
    }

    @NotNull
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.f11544f);
        sb.append('=');
        sb.append(this.f11545g);
        if (this.f11551m) {
            if (this.f11546h == Long.MIN_VALUE) {
                sb.append("; max-age=0");
            } else {
                sb.append("; expires=");
                Date toHttpDateString = new Date(this.f11546h);
                C4426c.a aVar = C4426c.f11731a;
                Intrinsics.checkParameterIsNotNull(toHttpDateString, "$this$toHttpDateString");
                String format = C4426c.f11731a.get().format(toHttpDateString);
                Intrinsics.checkExpressionValueIsNotNull(format, "STANDARD_DATE_FORMAT.get().format(this)");
                sb.append(format);
            }
        }
        if (!this.f11552n) {
            sb.append("; domain=");
            sb.append(this.f11547i);
        }
        sb.append("; path=");
        sb.append(this.f11548j);
        if (this.f11549k) {
            sb.append("; secure");
        }
        if (this.f11550l) {
            sb.append("; httponly");
        }
        String sb2 = sb.toString();
        Intrinsics.checkExpressionValueIsNotNull(sb2, "toString()");
        return sb2;
    }
}
