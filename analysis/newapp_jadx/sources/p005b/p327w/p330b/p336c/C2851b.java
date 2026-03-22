package p005b.p327w.p330b.p336c;

import android.content.Context;
import android.graphics.drawable.Drawable;
import androidx.annotation.CheckResult;
import androidx.annotation.DrawableRes;
import androidx.annotation.FloatRange;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RawRes;
import java.io.File;
import p005b.p143g.p144a.C1558h;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.ComponentCallbacks2C1559i;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1580l;
import p005b.p143g.p144a.p147m.C1581m;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p150t.AbstractC1643k;
import p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m;
import p005b.p143g.p144a.p147m.p156v.p157c.C1704i;
import p005b.p143g.p144a.p147m.p156v.p157c.C1713r;
import p005b.p143g.p144a.p147m.p156v.p157c.C1721z;
import p005b.p143g.p144a.p166q.AbstractC1774a;
import p005b.p143g.p144a.p166q.C1779f;
import p005b.p143g.p144a.p166q.InterfaceC1778e;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

/* renamed from: b.w.b.c.b */
/* loaded from: classes2.dex */
public class C2851b<TranscodeType> extends C1558h<TranscodeType> implements Cloneable {
    public C2851b(@NonNull ComponentCallbacks2C1553c componentCallbacks2C1553c, @NonNull ComponentCallbacks2C1559i componentCallbacks2C1559i, @NonNull Class<TranscodeType> cls, @NonNull Context context) {
        super(componentCallbacks2C1553c, componentCallbacks2C1559i, cls, context);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: B */
    public AbstractC1774a mo1072B(@NonNull C1581m c1581m, @NonNull Object obj) {
        return (C2851b) super.mo1072B(c1581m, obj);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: C */
    public AbstractC1774a mo1073C(@NonNull InterfaceC1579k interfaceC1579k) {
        return (C2851b) super.mo1073C(interfaceC1579k);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: D */
    public AbstractC1774a mo1074D(@FloatRange(from = 0.0d, m110to = 1.0d) float f2) {
        return (C2851b) super.mo1074D(f2);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: E */
    public AbstractC1774a mo1075E(boolean z) {
        return (C2851b) super.mo1075E(z);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: F */
    public AbstractC1774a mo1076F(@NonNull InterfaceC1586r interfaceC1586r) {
        return (C2851b) m1077G(interfaceC1586r, true);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: K */
    public AbstractC1774a mo1081K(boolean z) {
        return (C2851b) super.mo1081K(z);
    }

    @Override // p005b.p143g.p144a.C1558h
    @NonNull
    @CheckResult
    /* renamed from: L */
    public C1558h mo751L(@Nullable InterfaceC1778e interfaceC1778e) {
        super.mo751L(interfaceC1778e);
        return this;
    }

    @Override // p005b.p143g.p144a.C1558h
    @NonNull
    @CheckResult
    /* renamed from: M */
    public C1558h mo766a(@NonNull AbstractC1774a abstractC1774a) {
        return (C2851b) super.mo766a(abstractC1774a);
    }

    @Override // p005b.p143g.p144a.C1558h
    @NonNull
    @CheckResult
    /* renamed from: S */
    public C1558h mo758S(@Nullable InterfaceC1778e interfaceC1778e) {
        this.f1866J = null;
        super.mo751L(interfaceC1778e);
        return this;
    }

    @Override // p005b.p143g.p144a.C1558h
    @NonNull
    @CheckResult
    /* renamed from: T */
    public C1558h mo759T(@Nullable Drawable drawable) {
        this.f1865I = drawable;
        this.f1868L = true;
        return (C2851b) mo766a(C1779f.m1110L(AbstractC1643k.f2223b));
    }

    @Override // p005b.p143g.p144a.C1558h
    @NonNull
    @CheckResult
    /* renamed from: U */
    public C1558h mo760U(@Nullable File file) {
        this.f1865I = file;
        this.f1868L = true;
        return this;
    }

    @Override // p005b.p143g.p144a.C1558h
    @NonNull
    @CheckResult
    /* renamed from: V */
    public C1558h mo761V(@Nullable @DrawableRes @RawRes Integer num) {
        return (C2851b) super.mo761V(num);
    }

    @Override // p005b.p143g.p144a.C1558h
    @NonNull
    @CheckResult
    /* renamed from: W */
    public C1558h mo762W(@Nullable Object obj) {
        this.f1865I = obj;
        this.f1868L = true;
        return this;
    }

    @Override // p005b.p143g.p144a.C1558h
    @NonNull
    @CheckResult
    /* renamed from: X */
    public C1558h mo763X(@Nullable String str) {
        this.f1865I = str;
        this.f1868L = true;
        return this;
    }

    @Override // p005b.p143g.p144a.C1558h
    @NonNull
    @CheckResult
    /* renamed from: Y */
    public C1558h mo764Y(@Nullable byte[] bArr) {
        return (C2851b) super.mo764Y(bArr);
    }

    @Override // p005b.p143g.p144a.C1558h, p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: a */
    public AbstractC1774a mo766a(@NonNull AbstractC1774a abstractC1774a) {
        return (C2851b) super.mo766a(abstractC1774a);
    }

    @NonNull
    @CheckResult
    /* renamed from: a0 */
    public C2851b<TranscodeType> m3287a0(@NonNull AbstractC1774a<?> abstractC1774a) {
        return (C2851b) super.mo766a(abstractC1774a);
    }

    @NonNull
    @CheckResult
    /* renamed from: b0 */
    public C2851b<TranscodeType> m3288b0() {
        C2853d c2853d = C2853d.f7770a;
        int i2 = C2853d.f7775f;
        return (C2851b) mo1098y(i2).mo1088l(i2).mo1084f();
    }

    @Override // p005b.p143g.p144a.C1558h, p005b.p143g.p144a.p166q.AbstractC1774a
    @CheckResult
    /* renamed from: c0, reason: merged with bridge method [inline-methods] */
    public C2851b<TranscodeType> clone() {
        return (C2851b) super.clone();
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: d */
    public AbstractC1774a mo1083d() {
        return (C2851b) super.mo1083d();
    }

    @NonNull
    @CheckResult
    /* renamed from: d0 */
    public C2851b<TranscodeType> m3290d0() {
        C1558h<TranscodeType> m1078H = m1078H(AbstractC1708m.f2499a, new C1713r());
        m1078H.f2654B = true;
        return (C2851b) m1078H;
    }

    @NonNull
    @CheckResult
    /* renamed from: e0 */
    public C2851b<TranscodeType> m3291e0(@DrawableRes int i2) {
        return (C2851b) super.mo1098y(i2);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: f */
    public AbstractC1774a mo1084f() {
        return (C2851b) super.mo1084f();
    }

    @NonNull
    @CheckResult
    /* renamed from: f0 */
    public C2851b<TranscodeType> m3292f0() {
        C2853d c2853d = C2853d.f7770a;
        int i2 = C2853d.f7776g;
        return (C2851b) mo1098y(i2).mo1088l(i2).mo1083d();
    }

    @NonNull
    @CheckResult
    /* renamed from: g0 */
    public C2851b<TranscodeType> m3293g0(int i2) {
        C2853d c2853d = C2853d.f7770a;
        int i3 = C2853d.f7774e;
        return (C2851b) mo1098y(i3).mo1088l(i3).mo1083d().mo1076F(new C1580l(new C1704i(), new C1721z(C2354n.m2437V(ApplicationC2828a.f7672c, i2))));
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: h */
    public AbstractC1774a mo1085h(@NonNull Class cls) {
        return (C2851b) super.mo1085h(cls);
    }

    @NonNull
    @CheckResult
    /* renamed from: h0 */
    public C2851b<TranscodeType> m3294h0(boolean z) {
        return (C2851b) super.mo1075E(z);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: i */
    public AbstractC1774a mo1086i(@NonNull AbstractC1643k abstractC1643k) {
        return (C2851b) super.mo1086i(abstractC1643k);
    }

    @NonNull
    @CheckResult
    /* renamed from: i0 */
    public C2851b<TranscodeType> m3295i0() {
        C2853d c2853d = C2853d.f7770a;
        int i2 = C2853d.f7774e;
        return (C2851b) mo1098y(i2).mo1088l(i2);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: j */
    public AbstractC1774a mo1087j(@NonNull AbstractC1708m abstractC1708m) {
        return (C2851b) super.mo1087j(abstractC1708m);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: l */
    public AbstractC1774a mo1088l(@DrawableRes int i2) {
        return (C2851b) super.mo1088l(i2);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: m */
    public AbstractC1774a mo1089m(@DrawableRes int i2) {
        return (C2851b) super.mo1089m(i2);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: t */
    public AbstractC1774a mo1093t() {
        return (C2851b) super.mo1093t();
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: u */
    public AbstractC1774a mo1094u() {
        return (C2851b) super.mo1094u();
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: v */
    public AbstractC1774a mo1095v() {
        return (C2851b) super.mo1095v();
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: x */
    public AbstractC1774a mo1097x(int i2, int i3) {
        return (C2851b) super.mo1097x(i2, i3);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: y */
    public AbstractC1774a mo1098y(@DrawableRes int i2) {
        return (C2851b) super.mo1098y(i2);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: z */
    public AbstractC1774a mo1099z(@NonNull EnumC1556f enumC1556f) {
        return (C2851b) super.mo1099z(enumC1556f);
    }
}
