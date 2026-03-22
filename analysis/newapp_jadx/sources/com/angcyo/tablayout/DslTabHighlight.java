package com.angcyo.tablayout;

import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.view.View;
import android.view.ViewGroup;
import com.angcyo.tablayout.DslTabLayout;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u0000B\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0010\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0016\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0010\u0010\u001c\u001a\u00020\u001d2\u0006\u0010\u001e\u001a\u00020\u001fH\u0016J\u001a\u0010 \u001a\u00020\u001d2\u0006\u0010!\u001a\u00020\"2\b\u0010#\u001a\u0004\u0018\u00010$H\u0016J\n\u0010%\u001a\u0004\u0018\u00010&H\u0016R\u001c\u0010\u0005\u001a\u0004\u0018\u00010\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0007\u0010\b\"\u0004\b\t\u0010\nR\u001a\u0010\u000b\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\r\u0010\u000e\"\u0004\b\u000f\u0010\u0010R\u001a\u0010\u0011\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0012\u0010\u000e\"\u0004\b\u0013\u0010\u0010R\u001a\u0010\u0014\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0015\u0010\u000e\"\u0004\b\u0016\u0010\u0010R\u001a\u0010\u0017\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0018\u0010\u000e\"\u0004\b\u0019\u0010\u0010R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u001a\u0010\u001b¨\u0006'"}, m5311d2 = {"Lcom/angcyo/tablayout/DslTabHighlight;", "Lcom/angcyo/tablayout/DslGradientDrawable;", "tabLayout", "Lcom/angcyo/tablayout/DslTabLayout;", "(Lcom/angcyo/tablayout/DslTabLayout;)V", "highlightDrawable", "Landroid/graphics/drawable/Drawable;", "getHighlightDrawable", "()Landroid/graphics/drawable/Drawable;", "setHighlightDrawable", "(Landroid/graphics/drawable/Drawable;)V", "highlightHeight", "", "getHighlightHeight", "()I", "setHighlightHeight", "(I)V", "highlightHeightOffset", "getHighlightHeightOffset", "setHighlightHeightOffset", "highlightWidth", "getHighlightWidth", "setHighlightWidth", "highlightWidthOffset", "getHighlightWidthOffset", "setHighlightWidthOffset", "getTabLayout", "()Lcom/angcyo/tablayout/DslTabLayout;", "draw", "", "canvas", "Landroid/graphics/Canvas;", "initAttribute", "context", "Landroid/content/Context;", "attributeSet", "Landroid/util/AttributeSet;", "updateOriginDrawable", "Landroid/graphics/drawable/GradientDrawable;", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.o, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public class DslTabHighlight extends DslGradientDrawable {

    /* renamed from: q */
    @NotNull
    public final DslTabLayout f1615q;

    /* renamed from: r */
    @Nullable
    public Drawable f1616r;

    /* renamed from: s */
    public int f1617s;

    /* renamed from: t */
    public int f1618t;

    /* renamed from: u */
    public int f1619u;

    /* renamed from: v */
    public int f1620v;

    public DslTabHighlight(@NotNull DslTabLayout tabLayout) {
        Intrinsics.checkNotNullParameter(tabLayout, "tabLayout");
        this.f1615q = tabLayout;
        this.f1617s = -1;
        this.f1618t = -1;
    }

    @Override // com.angcyo.tablayout.DslGradientDrawable, android.graphics.drawable.Drawable
    public void draw(@NotNull Canvas canvas) {
        Drawable drawable;
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        View currentItemView = this.f1615q.getCurrentItemView();
        if (currentItemView != null) {
            ViewGroup.LayoutParams layoutParams = currentItemView.getLayoutParams();
            if (layoutParams instanceof DslTabLayout.C3200a) {
                drawable = ((DslTabLayout.C3200a) layoutParams).f8787g;
                if (drawable == null) {
                    drawable = this.f1616r;
                }
            } else {
                drawable = this.f1616r;
            }
            if (drawable == null) {
                return;
            }
            int i2 = this.f1617s;
            if (i2 == -2) {
                i2 = drawable.getIntrinsicWidth();
            } else if (i2 == -1) {
                i2 = currentItemView.getMeasuredWidth();
            }
            int i3 = i2 + this.f1619u;
            int i4 = this.f1618t;
            if (i4 == -2) {
                i4 = drawable.getIntrinsicHeight();
            } else if (i4 == -1) {
                i4 = currentItemView.getMeasuredHeight();
            }
            int i5 = i4 + this.f1620v;
            int right = ((currentItemView.getRight() - currentItemView.getLeft()) / 2) + currentItemView.getLeft();
            int bottom = ((currentItemView.getBottom() - currentItemView.getTop()) / 2) + currentItemView.getTop();
            int i6 = i3 / 2;
            int i7 = i5 / 2;
            drawable.setBounds(right - i6, bottom - i7, right + i6, bottom + i7);
            drawable.draw(canvas);
            canvas.save();
            if (this.f1615q.m3866d()) {
                canvas.translate(currentItemView.getLeft(), 0.0f);
            } else {
                canvas.translate(0.0f, currentItemView.getTop());
            }
            currentItemView.draw(canvas);
            canvas.restore();
        }
    }

    @Override // com.angcyo.tablayout.DslGradientDrawable
    @Nullable
    /* renamed from: k */
    public GradientDrawable mo657k() {
        GradientDrawable mo657k = super.mo657k();
        this.f1616r = this.f1565n;
        return mo657k;
    }
}
