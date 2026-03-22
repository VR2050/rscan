package p458k;

import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;

/* renamed from: k.e */
/* loaded from: classes3.dex */
public final class C4376e {

    /* renamed from: a */
    public static final a f11408a = new a(null);

    /* renamed from: b */
    public final boolean f11409b;

    /* renamed from: c */
    public final boolean f11410c;

    /* renamed from: d */
    public final int f11411d;

    /* renamed from: e */
    public final int f11412e;

    /* renamed from: f */
    public final boolean f11413f;

    /* renamed from: g */
    public final boolean f11414g;

    /* renamed from: h */
    public final boolean f11415h;

    /* renamed from: i */
    public final int f11416i;

    /* renamed from: j */
    public final int f11417j;

    /* renamed from: k */
    public final boolean f11418k;

    /* renamed from: l */
    public final boolean f11419l;

    /* renamed from: m */
    public final boolean f11420m;

    /* renamed from: n */
    public String f11421n;

    /* renamed from: k.e$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }

        /* renamed from: a */
        public final int m4960a(@NotNull String str, String str2, int i2) {
            int length = str.length();
            while (i2 < length) {
                if (StringsKt__StringsKt.contains$default((CharSequence) str2, str.charAt(i2), false, 2, (Object) null)) {
                    return i2;
                }
                i2++;
            }
            return str.length();
        }

        /* JADX WARN: Removed duplicated region for block: B:10:0x004a  */
        /* JADX WARN: Removed duplicated region for block: B:32:0x0104  */
        /* JADX WARN: Removed duplicated region for block: B:35:0x0108  */
        @kotlin.jvm.JvmStatic
        @org.jetbrains.annotations.NotNull
        /* renamed from: b */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final p458k.C4376e m4961b(@org.jetbrains.annotations.NotNull p458k.C4488y r33) {
            /*
                Method dump skipped, instructions count: 450
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p458k.C4376e.a.m4961b(k.y):k.e");
        }
    }

    static {
        TimeUnit timeUnit = TimeUnit.SECONDS;
        Intrinsics.checkParameterIsNotNull(timeUnit, "timeUnit");
        timeUnit.toSeconds(Integer.MAX_VALUE);
    }

    public C4376e(boolean z, boolean z2, int i2, int i3, boolean z3, boolean z4, boolean z5, int i4, int i5, boolean z6, boolean z7, boolean z8, String str, DefaultConstructorMarker defaultConstructorMarker) {
        this.f11409b = z;
        this.f11410c = z2;
        this.f11411d = i2;
        this.f11412e = i3;
        this.f11413f = z3;
        this.f11414g = z4;
        this.f11415h = z5;
        this.f11416i = i4;
        this.f11417j = i5;
        this.f11418k = z6;
        this.f11419l = z7;
        this.f11420m = z8;
        this.f11421n = str;
    }

    @NotNull
    public String toString() {
        String str = this.f11421n;
        if (str != null) {
            return str;
        }
        StringBuilder sb = new StringBuilder();
        if (this.f11409b) {
            sb.append("no-cache, ");
        }
        if (this.f11410c) {
            sb.append("no-store, ");
        }
        if (this.f11411d != -1) {
            sb.append("max-age=");
            sb.append(this.f11411d);
            sb.append(", ");
        }
        if (this.f11412e != -1) {
            sb.append("s-maxage=");
            sb.append(this.f11412e);
            sb.append(", ");
        }
        if (this.f11413f) {
            sb.append("private, ");
        }
        if (this.f11414g) {
            sb.append("public, ");
        }
        if (this.f11415h) {
            sb.append("must-revalidate, ");
        }
        if (this.f11416i != -1) {
            sb.append("max-stale=");
            sb.append(this.f11416i);
            sb.append(", ");
        }
        if (this.f11417j != -1) {
            sb.append("min-fresh=");
            sb.append(this.f11417j);
            sb.append(", ");
        }
        if (this.f11418k) {
            sb.append("only-if-cached, ");
        }
        if (this.f11419l) {
            sb.append("no-transform, ");
        }
        if (this.f11420m) {
            sb.append("immutable, ");
        }
        if (sb.length() == 0) {
            return "";
        }
        sb.delete(sb.length() - 2, sb.length());
        String sb2 = sb.toString();
        Intrinsics.checkExpressionValueIsNotNull(sb2, "StringBuilder().apply(builderAction).toString()");
        this.f11421n = sb2;
        return sb2;
    }
}
