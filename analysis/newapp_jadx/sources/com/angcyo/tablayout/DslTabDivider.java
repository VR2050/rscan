package com.angcyo.tablayout;

import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import com.angcyo.tablayout.DslTabLayout;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0017\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0016\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0010\u0010\u001f\u001a\u00020 2\u0006\u0010!\u001a\u00020\"H\u0016J\u0018\u0010#\u001a\u00020$2\u0006\u0010%\u001a\u00020\b2\u0006\u0010&\u001a\u00020\bH\u0016J\u0018\u0010'\u001a\u00020$2\u0006\u0010%\u001a\u00020\b2\u0006\u0010&\u001a\u00020\bH\u0016J\u001a\u0010(\u001a\u00020 2\u0006\u0010)\u001a\u00020*2\b\u0010+\u001a\u0004\u0018\u00010,H\u0016R\u0013\u0010\u0003\u001a\u0004\u0018\u00010\u00048F¢\u0006\u0006\u001a\u0004\b\u0005\u0010\u0006R\u001a\u0010\u0007\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\fR\u001a\u0010\r\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000e\u0010\n\"\u0004\b\u000f\u0010\fR\u001a\u0010\u0010\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0011\u0010\n\"\u0004\b\u0012\u0010\fR\u001a\u0010\u0013\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0014\u0010\n\"\u0004\b\u0015\u0010\fR\u001a\u0010\u0016\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0017\u0010\n\"\u0004\b\u0018\u0010\fR\u001a\u0010\u0019\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001a\u0010\n\"\u0004\b\u001b\u0010\fR\u001a\u0010\u001c\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001d\u0010\n\"\u0004\b\u001e\u0010\f¨\u0006-"}, m5311d2 = {"Lcom/angcyo/tablayout/DslTabDivider;", "Lcom/angcyo/tablayout/DslGradientDrawable;", "()V", "_tabLayout", "Lcom/angcyo/tablayout/DslTabLayout;", "get_tabLayout", "()Lcom/angcyo/tablayout/DslTabLayout;", "dividerHeight", "", "getDividerHeight", "()I", "setDividerHeight", "(I)V", "dividerMarginBottom", "getDividerMarginBottom", "setDividerMarginBottom", "dividerMarginLeft", "getDividerMarginLeft", "setDividerMarginLeft", "dividerMarginRight", "getDividerMarginRight", "setDividerMarginRight", "dividerMarginTop", "getDividerMarginTop", "setDividerMarginTop", "dividerShowMode", "getDividerShowMode", "setDividerShowMode", "dividerWidth", "getDividerWidth", "setDividerWidth", "draw", "", "canvas", "Landroid/graphics/Canvas;", "haveAfterDivider", "", "childIndex", "childCount", "haveBeforeDivider", "initAttribute", "context", "Landroid/content/Context;", "attributeSet", "Landroid/util/AttributeSet;", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.n, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public class DslTabDivider extends DslGradientDrawable {

    /* renamed from: s */
    public int f1610s;

    /* renamed from: t */
    public int f1611t;

    /* renamed from: u */
    public int f1612u;

    /* renamed from: v */
    public int f1613v;

    /* renamed from: q */
    public int f1608q = C4195m.m4801d0() * 2;

    /* renamed from: r */
    public int f1609r = C4195m.m4801d0() * 2;

    /* renamed from: w */
    public int f1614w = 2;

    @Override // com.angcyo.tablayout.DslGradientDrawable, android.graphics.drawable.Drawable
    public void draw(@NotNull Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        super.draw(canvas);
        Drawable drawable = this.f1565n;
        if (drawable == null) {
            return;
        }
        drawable.setBounds(getBounds());
        drawable.draw(canvas);
    }

    @Nullable
    /* renamed from: l */
    public final DslTabLayout m668l() {
        if (!(getCallback() instanceof DslTabLayout)) {
            return null;
        }
        Drawable.Callback callback = getCallback();
        Objects.requireNonNull(callback, "null cannot be cast to non-null type com.angcyo.tablayout.DslTabLayout");
        return (DslTabLayout) callback;
    }

    /* renamed from: m */
    public boolean m669m(int i2, int i3) {
        DslTabLayout m668l = m668l();
        return (m668l != null && m668l.m3866d() && m668l.m3867e() && i2 == i3 + (-1)) ? (this.f1614w & 1) != 0 : i2 == i3 - 1 && (this.f1614w & 4) != 0;
    }

    /* renamed from: n */
    public boolean m670n(int i2) {
        DslTabLayout m668l = m668l();
        return (m668l != null && m668l.m3866d() && m668l.m3867e()) ? i2 == 0 ? (this.f1614w & 4) != 0 : (this.f1614w & 2) != 0 : i2 == 0 ? (this.f1614w & 1) != 0 : (this.f1614w & 2) != 0;
    }
}
