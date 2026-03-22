package com.angcyo.tablayout;

import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\b\n\u0002\u0010\u000b\n\u0002\b\u000b\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0016\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0010\u0010\u001e\u001a\u00020\u001f2\u0006\u0010 \u001a\u00020!H\u0016J\u000e\u0010\"\u001a\u00020\u001f2\u0006\u0010 \u001a\u00020!J\u001a\u0010#\u001a\u00020\u001f2\u0006\u0010$\u001a\u00020%2\b\u0010&\u001a\u0004\u0018\u00010'H\u0016J(\u0010(\u001a\u00020\u001f2\u0006\u0010)\u001a\u00020*2\u0006\u0010+\u001a\u00020,2\u0006\u0010-\u001a\u00020\n2\u0006\u0010.\u001a\u00020\u0013H\u0016R\u001c\u0010\u0003\u001a\u0004\u0018\u00010\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\bR\u001a\u0010\t\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000eR\u001a\u0010\u000f\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0010\u0010\f\"\u0004\b\u0011\u0010\u000eR\u001a\u0010\u0012\u001a\u00020\u0013X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0014\u0010\u0015\"\u0004\b\u0016\u0010\u0017R\u001c\u0010\u0018\u001a\u0004\u0018\u00010\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0019\u0010\u0006\"\u0004\b\u001a\u0010\bR\u001c\u0010\u001b\u001a\u0004\u0018\u00010\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001c\u0010\u0006\"\u0004\b\u001d\u0010\b¨\u0006/"}, m5311d2 = {"Lcom/angcyo/tablayout/DslTabBorder;", "Lcom/angcyo/tablayout/DslGradientDrawable;", "()V", "borderBackgroundDrawable", "Landroid/graphics/drawable/Drawable;", "getBorderBackgroundDrawable", "()Landroid/graphics/drawable/Drawable;", "setBorderBackgroundDrawable", "(Landroid/graphics/drawable/Drawable;)V", "borderBackgroundHeightOffset", "", "getBorderBackgroundHeightOffset", "()I", "setBorderBackgroundHeightOffset", "(I)V", "borderBackgroundWidthOffset", "getBorderBackgroundWidthOffset", "setBorderBackgroundWidthOffset", "borderDrawItemBackground", "", "getBorderDrawItemBackground", "()Z", "setBorderDrawItemBackground", "(Z)V", "itemDeselectBgDrawable", "getItemDeselectBgDrawable", "setItemDeselectBgDrawable", "itemSelectBgDrawable", "getItemSelectBgDrawable", "setItemSelectBgDrawable", "draw", "", "canvas", "Landroid/graphics/Canvas;", "drawBorderBackground", "initAttribute", "context", "Landroid/content/Context;", "attributeSet", "Landroid/util/AttributeSet;", "updateItemBackground", "tabLayout", "Lcom/angcyo/tablayout/DslTabLayout;", "itemView", "Landroid/view/View;", "index", "select", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.m, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public class DslTabBorder extends DslGradientDrawable {

    /* renamed from: q */
    public boolean f1603q = true;

    /* renamed from: r */
    @Nullable
    public Drawable f1604r;

    /* renamed from: s */
    public int f1605s;

    /* renamed from: t */
    public int f1606t;

    /* renamed from: u */
    @Nullable
    public Drawable f1607u;

    @Override // com.angcyo.tablayout.DslGradientDrawable, android.graphics.drawable.Drawable
    public void draw(@NotNull Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        super.draw(canvas);
        Drawable drawable = this.f1565n;
        if (drawable == null) {
            return;
        }
        drawable.setBounds(m646c(), m645b(), m651h() - m647d(), m650g() - m645b());
        drawable.draw(canvas);
    }

    /* renamed from: l */
    public final void m667l(@NotNull Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        super.draw(canvas);
        Drawable drawable = this.f1604r;
        if (drawable == null) {
            return;
        }
        drawable.setBounds(m646c(), m645b(), m651h() - m647d(), m650g() - m645b());
        drawable.draw(canvas);
    }
}
