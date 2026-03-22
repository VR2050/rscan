package com.angcyo.tablayout;

import androidx.annotation.Px;
import androidx.core.internal.view.SupportMenu;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u0007\n\u0002\b\f\n\u0002\u0010\u000b\n\u0002\bP\b\u0086\b\u0018\u00002\u00020\u0001BÙ\u0001\u0012\n\b\u0002\u0010\u0002\u001a\u0004\u0018\u00010\u0003\u0012\b\b\u0002\u0010\u0004\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0006\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0007\u001a\u00020\u0005\u0012\b\b\u0002\u0010\b\u001a\u00020\u0005\u0012\b\b\u0002\u0010\t\u001a\u00020\u0005\u0012\b\b\u0003\u0010\n\u001a\u00020\u000b\u0012\b\b\u0002\u0010\f\u001a\u00020\u0005\u0012\b\b\u0002\u0010\r\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u000e\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u000f\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0010\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0011\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0012\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0013\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0014\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0015\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0016\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0017\u001a\u00020\u0018\u0012\b\b\u0002\u0010\u0019\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u001a\u001a\u00020\u0005¢\u0006\u0002\u0010\u001bJ\u000b\u0010N\u001a\u0004\u0018\u00010\u0003HÆ\u0003J\t\u0010O\u001a\u00020\u0005HÆ\u0003J\t\u0010P\u001a\u00020\u0005HÆ\u0003J\t\u0010Q\u001a\u00020\u0005HÆ\u0003J\t\u0010R\u001a\u00020\u0005HÆ\u0003J\t\u0010S\u001a\u00020\u0005HÆ\u0003J\t\u0010T\u001a\u00020\u0005HÆ\u0003J\t\u0010U\u001a\u00020\u0005HÆ\u0003J\t\u0010V\u001a\u00020\u0005HÆ\u0003J\t\u0010W\u001a\u00020\u0005HÆ\u0003J\t\u0010X\u001a\u00020\u0018HÆ\u0003J\t\u0010Y\u001a\u00020\u0005HÆ\u0003J\t\u0010Z\u001a\u00020\u0005HÆ\u0003J\t\u0010[\u001a\u00020\u0005HÆ\u0003J\t\u0010\\\u001a\u00020\u0005HÆ\u0003J\t\u0010]\u001a\u00020\u0005HÆ\u0003J\t\u0010^\u001a\u00020\u0005HÆ\u0003J\t\u0010_\u001a\u00020\u0005HÆ\u0003J\t\u0010`\u001a\u00020\u000bHÆ\u0003J\t\u0010a\u001a\u00020\u0005HÆ\u0003J\t\u0010b\u001a\u00020\u0005HÆ\u0003JÝ\u0001\u0010c\u001a\u00020\u00002\n\b\u0002\u0010\u0002\u001a\u0004\u0018\u00010\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00052\b\b\u0002\u0010\u0006\u001a\u00020\u00052\b\b\u0002\u0010\u0007\u001a\u00020\u00052\b\b\u0002\u0010\b\u001a\u00020\u00052\b\b\u0002\u0010\t\u001a\u00020\u00052\b\b\u0003\u0010\n\u001a\u00020\u000b2\b\b\u0002\u0010\f\u001a\u00020\u00052\b\b\u0002\u0010\r\u001a\u00020\u00052\b\b\u0002\u0010\u000e\u001a\u00020\u00052\b\b\u0002\u0010\u000f\u001a\u00020\u00052\b\b\u0002\u0010\u0010\u001a\u00020\u00052\b\b\u0002\u0010\u0011\u001a\u00020\u00052\b\b\u0002\u0010\u0012\u001a\u00020\u00052\b\b\u0002\u0010\u0013\u001a\u00020\u00052\b\b\u0002\u0010\u0014\u001a\u00020\u00052\b\b\u0002\u0010\u0015\u001a\u00020\u00052\b\b\u0002\u0010\u0016\u001a\u00020\u00052\b\b\u0002\u0010\u0017\u001a\u00020\u00182\b\b\u0002\u0010\u0019\u001a\u00020\u00052\b\b\u0002\u0010\u001a\u001a\u00020\u0005HÆ\u0001J\u0013\u0010d\u001a\u00020\u00182\b\u0010e\u001a\u0004\u0018\u00010\u0001HÖ\u0003J\t\u0010f\u001a\u00020\u0005HÖ\u0001J\t\u0010g\u001a\u00020\u0003HÖ\u0001R\u001a\u0010\u0016\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001c\u0010\u001d\"\u0004\b\u001e\u0010\u001fR\u001a\u0010\u0010\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b \u0010\u001d\"\u0004\b!\u0010\u001fR\u001a\u0010\u0011\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\"\u0010\u001d\"\u0004\b#\u0010\u001fR\u001a\u0010\f\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b$\u0010\u001d\"\u0004\b%\u0010\u001fR\u001a\u0010\u0004\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b&\u0010\u001d\"\u0004\b'\u0010\u001fR\u001a\u0010\u0017\u001a\u00020\u0018X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b(\u0010)\"\u0004\b*\u0010+R\u001a\u0010\u0019\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b,\u0010\u001d\"\u0004\b-\u0010\u001fR\u001a\u0010\u001a\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b.\u0010\u001d\"\u0004\b/\u0010\u001fR\u001a\u0010\u000e\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b0\u0010\u001d\"\u0004\b1\u0010\u001fR\u001a\u0010\u000f\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b2\u0010\u001d\"\u0004\b3\u0010\u001fR\u001a\u0010\u0015\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b4\u0010\u001d\"\u0004\b5\u0010\u001fR\u001a\u0010\u0012\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b6\u0010\u001d\"\u0004\b7\u0010\u001fR\u001a\u0010\u0013\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b8\u0010\u001d\"\u0004\b9\u0010\u001fR\u001a\u0010\u0014\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b:\u0010\u001d\"\u0004\b;\u0010\u001fR\u001a\u0010\r\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b<\u0010\u001d\"\u0004\b=\u0010\u001fR\u001a\u0010\u0006\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b>\u0010\u001d\"\u0004\b?\u0010\u001fR\u001a\u0010\u0007\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b@\u0010\u001d\"\u0004\bA\u0010\u001fR\u001a\u0010\b\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bB\u0010\u001d\"\u0004\bC\u0010\u001fR\u001c\u0010\u0002\u001a\u0004\u0018\u00010\u0003X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bD\u0010E\"\u0004\bF\u0010GR\u001a\u0010\t\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bH\u0010\u001d\"\u0004\bI\u0010\u001fR\u001a\u0010\n\u001a\u00020\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bJ\u0010K\"\u0004\bL\u0010M¨\u0006h"}, m5311d2 = {"Lcom/angcyo/tablayout/TabBadgeConfig;", "", "badgeText", "", "badgeGravity", "", "badgeSolidColor", "badgeStrokeColor", "badgeStrokeWidth", "badgeTextColor", "badgeTextSize", "", "badgeCircleRadius", "badgeRadius", "badgeOffsetX", "badgeOffsetY", "badgeCircleOffsetX", "badgeCircleOffsetY", "badgePaddingLeft", "badgePaddingRight", "badgePaddingTop", "badgePaddingBottom", "badgeAnchorChildIndex", "badgeIgnoreChildPadding", "", "badgeMinHeight", "badgeMinWidth", "(Ljava/lang/String;IIIIIFIIIIIIIIIIIZII)V", "getBadgeAnchorChildIndex", "()I", "setBadgeAnchorChildIndex", "(I)V", "getBadgeCircleOffsetX", "setBadgeCircleOffsetX", "getBadgeCircleOffsetY", "setBadgeCircleOffsetY", "getBadgeCircleRadius", "setBadgeCircleRadius", "getBadgeGravity", "setBadgeGravity", "getBadgeIgnoreChildPadding", "()Z", "setBadgeIgnoreChildPadding", "(Z)V", "getBadgeMinHeight", "setBadgeMinHeight", "getBadgeMinWidth", "setBadgeMinWidth", "getBadgeOffsetX", "setBadgeOffsetX", "getBadgeOffsetY", "setBadgeOffsetY", "getBadgePaddingBottom", "setBadgePaddingBottom", "getBadgePaddingLeft", "setBadgePaddingLeft", "getBadgePaddingRight", "setBadgePaddingRight", "getBadgePaddingTop", "setBadgePaddingTop", "getBadgeRadius", "setBadgeRadius", "getBadgeSolidColor", "setBadgeSolidColor", "getBadgeStrokeColor", "setBadgeStrokeColor", "getBadgeStrokeWidth", "setBadgeStrokeWidth", "getBadgeText", "()Ljava/lang/String;", "setBadgeText", "(Ljava/lang/String;)V", "getBadgeTextColor", "setBadgeTextColor", "getBadgeTextSize", "()F", "setBadgeTextSize", "(F)V", "component1", "component10", "component11", "component12", "component13", "component14", "component15", "component16", "component17", "component18", "component19", "component2", "component20", "component21", "component3", "component4", "component5", "component6", "component7", "component8", "component9", "copy", "equals", "other", "hashCode", "toString", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.z, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public final /* data */ class TabBadgeConfig {

    /* renamed from: a */
    @Nullable
    public String f1682a;

    /* renamed from: b */
    public int f1683b;

    /* renamed from: c */
    public int f1684c;

    /* renamed from: d */
    public int f1685d;

    /* renamed from: e */
    public int f1686e;

    /* renamed from: f */
    public int f1687f;

    /* renamed from: g */
    public float f1688g;

    /* renamed from: h */
    public int f1689h;

    /* renamed from: i */
    public int f1690i;

    /* renamed from: j */
    public int f1691j;

    /* renamed from: k */
    public int f1692k;

    /* renamed from: l */
    public int f1693l;

    /* renamed from: m */
    public int f1694m;

    /* renamed from: n */
    public int f1695n;

    /* renamed from: o */
    public int f1696o;

    /* renamed from: p */
    public int f1697p;

    /* renamed from: q */
    public int f1698q;

    /* renamed from: r */
    public int f1699r;

    /* renamed from: s */
    public boolean f1700s;

    /* renamed from: t */
    public int f1701t;

    /* renamed from: u */
    public int f1702u;

    public TabBadgeConfig() {
        this(null, 0, 0, 0, 0, 0, 0.0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0, 0, 2097151);
    }

    public TabBadgeConfig(@Nullable String str, int i2, int i3, int i4, int i5, int i6, @Px float f2, int i7, int i8, int i9, int i10, int i11, int i12, int i13, int i14, int i15, int i16, int i17, boolean z, int i18, int i19) {
        this.f1682a = str;
        this.f1683b = i2;
        this.f1684c = i3;
        this.f1685d = i4;
        this.f1686e = i5;
        this.f1687f = i6;
        this.f1688g = f2;
        this.f1689h = i7;
        this.f1690i = i8;
        this.f1691j = i9;
        this.f1692k = i10;
        this.f1693l = i11;
        this.f1694m = i12;
        this.f1695n = i13;
        this.f1696o = i14;
        this.f1697p = i15;
        this.f1698q = i16;
        this.f1699r = i17;
        this.f1700s = z;
        this.f1701t = i18;
        this.f1702u = i19;
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof TabBadgeConfig)) {
            return false;
        }
        TabBadgeConfig tabBadgeConfig = (TabBadgeConfig) other;
        return Intrinsics.areEqual(this.f1682a, tabBadgeConfig.f1682a) && this.f1683b == tabBadgeConfig.f1683b && this.f1684c == tabBadgeConfig.f1684c && this.f1685d == tabBadgeConfig.f1685d && this.f1686e == tabBadgeConfig.f1686e && this.f1687f == tabBadgeConfig.f1687f && Intrinsics.areEqual((Object) Float.valueOf(this.f1688g), (Object) Float.valueOf(tabBadgeConfig.f1688g)) && this.f1689h == tabBadgeConfig.f1689h && this.f1690i == tabBadgeConfig.f1690i && this.f1691j == tabBadgeConfig.f1691j && this.f1692k == tabBadgeConfig.f1692k && this.f1693l == tabBadgeConfig.f1693l && this.f1694m == tabBadgeConfig.f1694m && this.f1695n == tabBadgeConfig.f1695n && this.f1696o == tabBadgeConfig.f1696o && this.f1697p == tabBadgeConfig.f1697p && this.f1698q == tabBadgeConfig.f1698q && this.f1699r == tabBadgeConfig.f1699r && this.f1700s == tabBadgeConfig.f1700s && this.f1701t == tabBadgeConfig.f1701t && this.f1702u == tabBadgeConfig.f1702u;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public int hashCode() {
        String str = this.f1682a;
        int floatToIntBits = (((((((((((((((((((((((Float.floatToIntBits(this.f1688g) + ((((((((((((str == null ? 0 : str.hashCode()) * 31) + this.f1683b) * 31) + this.f1684c) * 31) + this.f1685d) * 31) + this.f1686e) * 31) + this.f1687f) * 31)) * 31) + this.f1689h) * 31) + this.f1690i) * 31) + this.f1691j) * 31) + this.f1692k) * 31) + this.f1693l) * 31) + this.f1694m) * 31) + this.f1695n) * 31) + this.f1696o) * 31) + this.f1697p) * 31) + this.f1698q) * 31) + this.f1699r) * 31;
        boolean z = this.f1700s;
        int i2 = z;
        if (z != 0) {
            i2 = 1;
        }
        return ((((floatToIntBits + i2) * 31) + this.f1701t) * 31) + this.f1702u;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("TabBadgeConfig(badgeText=");
        m586H.append((Object) this.f1682a);
        m586H.append(", badgeGravity=");
        m586H.append(this.f1683b);
        m586H.append(", badgeSolidColor=");
        m586H.append(this.f1684c);
        m586H.append(", badgeStrokeColor=");
        m586H.append(this.f1685d);
        m586H.append(", badgeStrokeWidth=");
        m586H.append(this.f1686e);
        m586H.append(", badgeTextColor=");
        m586H.append(this.f1687f);
        m586H.append(", badgeTextSize=");
        m586H.append(this.f1688g);
        m586H.append(", badgeCircleRadius=");
        m586H.append(this.f1689h);
        m586H.append(", badgeRadius=");
        m586H.append(this.f1690i);
        m586H.append(", badgeOffsetX=");
        m586H.append(this.f1691j);
        m586H.append(", badgeOffsetY=");
        m586H.append(this.f1692k);
        m586H.append(", badgeCircleOffsetX=");
        m586H.append(this.f1693l);
        m586H.append(", badgeCircleOffsetY=");
        m586H.append(this.f1694m);
        m586H.append(", badgePaddingLeft=");
        m586H.append(this.f1695n);
        m586H.append(", badgePaddingRight=");
        m586H.append(this.f1696o);
        m586H.append(", badgePaddingTop=");
        m586H.append(this.f1697p);
        m586H.append(", badgePaddingBottom=");
        m586H.append(this.f1698q);
        m586H.append(", badgeAnchorChildIndex=");
        m586H.append(this.f1699r);
        m586H.append(", badgeIgnoreChildPadding=");
        m586H.append(this.f1700s);
        m586H.append(", badgeMinHeight=");
        m586H.append(this.f1701t);
        m586H.append(", badgeMinWidth=");
        return C1499a.m579A(m586H, this.f1702u, ')');
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ TabBadgeConfig(String str, int i2, int i3, int i4, int i5, int i6, float f2, int i7, int i8, int i9, int i10, int i11, int i12, int i13, int i14, int i15, int i16, int i17, boolean z, int i18, int i19, int i20) {
        this(null, (i20 & 2) != 0 ? 17 : i2, (i20 & 4) != 0 ? SupportMenu.CATEGORY_MASK : i3, (i20 & 8) != 0 ? 0 : i4, (i20 & 16) != 0 ? 0 : i5, (i20 & 32) != 0 ? -1 : i6, (i20 & 64) != 0 ? 12 * C4195m.m4797b0() : f2, (i20 & 128) != 0 ? C4195m.m4801d0() * 4 : i7, (i20 & 256) != 0 ? C4195m.m4801d0() * 10 : i8, (i20 & 512) != 0 ? 0 : i9, (i20 & 1024) != 0 ? 0 : i10, (i20 & 2048) != 0 ? 0 : i11, (i20 & 4096) != 0 ? 0 : i12, (i20 & 8192) != 0 ? C4195m.m4801d0() * 4 : i13, (i20 & 16384) != 0 ? C4195m.m4801d0() * 4 : i14, (i20 & 32768) != 0 ? 0 : i15, (i20 & 65536) != 0 ? 0 : i16, (i20 & 131072) != 0 ? -1 : i17, (i20 & 262144) != 0 ? true : z, (i20 & 524288) != 0 ? -2 : i18, (i20 & 1048576) != 0 ? -1 : i19);
        int i21 = i20 & 1;
    }
}
