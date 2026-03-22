package p005b.p081b0.p082a.p083a;

import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import androidx.annotation.ColorInt;
import androidx.annotation.Dimension;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.b0.a.a.b */
/* loaded from: classes2.dex */
public final class C1325b {

    /* renamed from: A */
    public int f1074A;

    /* renamed from: B */
    public int f1075B;

    /* renamed from: C */
    public int f1076C;

    /* renamed from: D */
    @NotNull
    public String f1077D;

    /* renamed from: E */
    @Nullable
    public Drawable f1078E;

    /* renamed from: F */
    public int f1079F;

    /* renamed from: G */
    public int f1080G;

    /* renamed from: H */
    public int f1081H;

    /* renamed from: I */
    public int f1082I;

    /* renamed from: a */
    @NotNull
    public final EnumC1326c f1083a;

    /* renamed from: b */
    @Dimension(unit = 1)
    @Nullable
    public Float f1084b;

    /* renamed from: c */
    @ColorInt
    public int f1085c;

    /* renamed from: d */
    public int f1086d;

    /* renamed from: e */
    public int f1087e;

    /* renamed from: f */
    @Nullable
    public Float f1088f;

    /* renamed from: g */
    public final float f1089g;

    /* renamed from: h */
    public float f1090h;

    /* renamed from: i */
    public float f1091i;

    /* renamed from: j */
    public float f1092j;

    /* renamed from: k */
    public float f1093k;

    /* renamed from: l */
    @Nullable
    public Integer f1094l;

    /* renamed from: m */
    public final int f1095m;

    /* renamed from: n */
    public int f1096n;

    /* renamed from: o */
    public int f1097o;

    /* renamed from: p */
    public int f1098p;

    /* renamed from: q */
    public int f1099q;

    /* renamed from: r */
    @ColorInt
    public int f1100r;

    /* renamed from: s */
    @Nullable
    public Drawable f1101s;

    /* renamed from: t */
    @ColorInt
    @Nullable
    public Integer f1102t;

    /* renamed from: u */
    @ColorInt
    @Nullable
    public Integer f1103u;

    /* renamed from: v */
    @NotNull
    public GradientDrawable.Orientation f1104v;

    /* renamed from: w */
    public int f1105w;

    /* renamed from: x */
    @ColorInt
    public int f1106x;

    /* renamed from: y */
    @NotNull
    public EnumC1324a f1107y;

    /* renamed from: z */
    public int f1108z;

    public C1325b(@NotNull EnumC1326c type) {
        Intrinsics.checkNotNullParameter(type, "type");
        this.f1083a = type;
        this.f1085c = -1;
        float m4799c0 = C4195m.m4799c0(2);
        this.f1089g = m4799c0;
        this.f1090h = m4799c0;
        this.f1091i = m4799c0;
        this.f1092j = m4799c0;
        this.f1093k = m4799c0;
        int m4799c02 = C4195m.m4799c0(5);
        this.f1095m = m4799c02;
        this.f1097o = m4799c02;
        this.f1099q = m4799c02;
        this.f1100r = -7829368;
        this.f1104v = GradientDrawable.Orientation.LEFT_RIGHT;
        this.f1106x = -7829368;
        this.f1107y = EnumC1324a.LEFT;
        this.f1076C = 1;
        this.f1077D = "";
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C1325b) && this.f1083a == ((C1325b) obj).f1083a;
    }

    public int hashCode() {
        return this.f1083a.hashCode();
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("TagConfig(type=");
        m586H.append(this.f1083a);
        m586H.append(')');
        return m586H.toString();
    }
}
