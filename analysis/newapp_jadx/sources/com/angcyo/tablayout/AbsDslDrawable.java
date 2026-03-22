package com.angcyo.tablayout;

import android.content.res.ColorStateList;
import android.graphics.BlendMode;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.text.TextPaint;
import android.view.View;
import androidx.constraintlayout.motion.widget.Key;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5310d1 = {"\u0000\u0088\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\u0015\n\u0002\b\u000f\n\u0002\u0010\u0007\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b&\u0018\u0000 f2\u00020\u0001:\u0001fB\u0005¢\u0006\u0002\u0010\u0002J\u0010\u0010/\u001a\u0002002\u0006\u00101\u001a\u000202H\u0016J\b\u00103\u001a\u00020\u0010H\u0016J\n\u00104\u001a\u0004\u0018\u000105H\u0016J\u0010\u00106\u001a\u0002002\u0006\u00107\u001a\u00020\bH\u0016J\b\u00108\u001a\u00020\u0010H\u0016J\b\u00109\u001a\u00020\u0010H\u0016J\b\u0010:\u001a\u00020\u0010H\u0016J\b\u0010;\u001a\u00020\u0010H\u0016J\b\u0010<\u001a\u00020\u0010H\u0016J\u001c\u0010=\u001a\u0002002\u0006\u0010>\u001a\u00020?2\n\b\u0002\u0010@\u001a\u0004\u0018\u00010AH\u0016J\b\u0010B\u001a\u00020\u0016H\u0016J\b\u0010C\u001a\u00020\u0001H\u0016J\u0012\u0010D\u001a\u0002002\b\u0010E\u001a\u0004\u0018\u00010\bH\u0014J\u0010\u0010F\u001a\u00020\u00162\u0006\u0010G\u001a\u00020\u0010H\u0014J\u0012\u0010H\u001a\u00020\u00162\b\u0010I\u001a\u0004\u0018\u00010JH\u0014J\u0010\u0010K\u001a\u0002002\u0006\u0010L\u001a\u00020\u0010H\u0016J\u0010\u0010M\u001a\u0002002\u0006\u0010E\u001a\u00020\bH\u0016J(\u0010M\u001a\u0002002\u0006\u0010N\u001a\u00020\u00102\u0006\u0010O\u001a\u00020\u00102\u0006\u0010P\u001a\u00020\u00102\u0006\u0010Q\u001a\u00020\u0010H\u0016J\u0012\u0010R\u001a\u0002002\b\u0010S\u001a\u0004\u0018\u000105H\u0016J\u0010\u0010T\u001a\u0002002\u0006\u0010U\u001a\u00020\u0016H\u0016J\u0010\u0010V\u001a\u0002002\u0006\u0010W\u001a\u00020\u0016H\u0016J\u0018\u0010X\u001a\u0002002\u0006\u0010Y\u001a\u00020Z2\u0006\u0010[\u001a\u00020ZH\u0016J(\u0010\\\u001a\u0002002\u0006\u0010N\u001a\u00020\u00102\u0006\u0010O\u001a\u00020\u00102\u0006\u0010P\u001a\u00020\u00102\u0006\u0010Q\u001a\u00020\u0010H\u0016J\u0012\u0010]\u001a\u0002002\b\u0010^\u001a\u0004\u0018\u00010_H\u0016J\u0012\u0010`\u001a\u0002002\b\u0010a\u001a\u0004\u0018\u00010bH\u0016J\u0012\u0010c\u001a\u0002002\b\u0010d\u001a\u0004\u0018\u00010eH\u0016R\u0013\u0010\u0003\u001a\u0004\u0018\u00010\u00048F¢\u0006\u0006\u001a\u0004\b\u0005\u0010\u0006R\u0011\u0010\u0007\u001a\u00020\b¢\u0006\b\n\u0000\u001a\u0004\b\t\u0010\nR\u0011\u0010\u000b\u001a\u00020\f¢\u0006\b\n\u0000\u001a\u0004\b\r\u0010\u000eR\u001a\u0010\u000f\u001a\u00020\u0010X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0011\u0010\u0012\"\u0004\b\u0013\u0010\u0014R\u0011\u0010\u0015\u001a\u00020\u00168F¢\u0006\u0006\u001a\u0004\b\u0015\u0010\u0017R\u0011\u0010\u0018\u001a\u00020\u00168F¢\u0006\u0006\u001a\u0004\b\u0018\u0010\u0017R\u0011\u0010\u0019\u001a\u00020\u00108F¢\u0006\u0006\u001a\u0004\b\u001a\u0010\u0012R\u0011\u0010\u001b\u001a\u00020\u00108F¢\u0006\u0006\u001a\u0004\b\u001c\u0010\u0012R\u0011\u0010\u001d\u001a\u00020\u00108F¢\u0006\u0006\u001a\u0004\b\u001e\u0010\u0012R\u0011\u0010\u001f\u001a\u00020\u00108F¢\u0006\u0006\u001a\u0004\b \u0010\u0012R\u001b\u0010!\u001a\u00020\"8FX\u0086\u0084\u0002¢\u0006\f\n\u0004\b%\u0010&\u001a\u0004\b#\u0010$R\u0011\u0010'\u001a\u00020\u00108F¢\u0006\u0006\u001a\u0004\b(\u0010\u0012R\u0011\u0010)\u001a\u00020\u00108F¢\u0006\u0006\u001a\u0004\b*\u0010\u0012R\u0011\u0010+\u001a\u00020\u00108F¢\u0006\u0006\u001a\u0004\b,\u0010\u0012R\u0011\u0010-\u001a\u00020\u00108F¢\u0006\u0006\u001a\u0004\b.\u0010\u0012¨\u0006g"}, m5311d2 = {"Lcom/angcyo/tablayout/AbsDslDrawable;", "Landroid/graphics/drawable/Drawable;", "()V", "attachView", "Landroid/view/View;", "getAttachView", "()Landroid/view/View;", "drawRect", "Landroid/graphics/Rect;", "getDrawRect", "()Landroid/graphics/Rect;", "drawRectF", "Landroid/graphics/RectF;", "getDrawRectF", "()Landroid/graphics/RectF;", "drawType", "", "getDrawType", "()I", "setDrawType", "(I)V", "isInEditMode", "", "()Z", "isViewRtl", "paddingBottom", "getPaddingBottom", "paddingLeft", "getPaddingLeft", "paddingRight", "getPaddingRight", "paddingTop", "getPaddingTop", "textPaint", "Landroid/text/TextPaint;", "getTextPaint", "()Landroid/text/TextPaint;", "textPaint$delegate", "Lkotlin/Lazy;", "viewDrawHeight", "getViewDrawHeight", "viewDrawWidth", "getViewDrawWidth", "viewHeight", "getViewHeight", "viewWidth", "getViewWidth", "draw", "", "canvas", "Landroid/graphics/Canvas;", "getAlpha", "getColorFilter", "Landroid/graphics/ColorFilter;", "getHotspotBounds", "outRect", "getIntrinsicHeight", "getIntrinsicWidth", "getMinimumHeight", "getMinimumWidth", "getOpacity", "initAttribute", "context", "Landroid/content/Context;", "attributeSet", "Landroid/util/AttributeSet;", "isFilterBitmap", "mutate", "onBoundsChange", "bounds", "onLevelChange", "level", "onStateChange", "state", "", "setAlpha", Key.ALPHA, "setBounds", "left", "top", "right", "bottom", "setColorFilter", "colorFilter", "setDither", "dither", "setFilterBitmap", "filter", "setHotspot", "x", "", "y", "setHotspotBounds", "setTintBlendMode", "blendMode", "Landroid/graphics/BlendMode;", "setTintList", "tint", "Landroid/content/res/ColorStateList;", "setTintMode", "tintMode", "Landroid/graphics/PorterDuff$Mode;", "Companion", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.d, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public abstract class AbsDslDrawable extends Drawable {

    /* renamed from: a */
    @NotNull
    public final Lazy f1527a = LazyKt__LazyJVMKt.lazy(a.f1528c);

    @Metadata(m5310d1 = {"\u0000\b\n\u0000\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001H\n¢\u0006\u0002\b\u0002"}, m5311d2 = {"<anonymous>", "Landroid/text/TextPaint;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.d$a */
    public static final class a extends Lambda implements Function0<TextPaint> {

        /* renamed from: c */
        public static final a f1528c = new a();

        public a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public TextPaint invoke() {
            TextPaint textPaint = new TextPaint(1);
            textPaint.setFilterBitmap(true);
            textPaint.setStyle(Paint.Style.FILL);
            textPaint.setTextSize(C4195m.m4797b0() * 12);
            return textPaint;
        }
    }

    public AbsDslDrawable() {
        new Rect();
        new RectF();
    }

    @Nullable
    /* renamed from: a */
    public final View m644a() {
        if (!(getCallback() instanceof View)) {
            return null;
        }
        Drawable.Callback callback = getCallback();
        if (callback instanceof View) {
            return (View) callback;
        }
        return null;
    }

    /* renamed from: b */
    public final int m645b() {
        View m644a = m644a();
        if (m644a == null) {
            return 0;
        }
        return m644a.getPaddingBottom();
    }

    /* renamed from: c */
    public final int m646c() {
        View m644a = m644a();
        if (m644a == null) {
            return 0;
        }
        return m644a.getPaddingLeft();
    }

    /* renamed from: d */
    public final int m647d() {
        View m644a = m644a();
        if (m644a == null) {
            return 0;
        }
        return m644a.getPaddingRight();
    }

    /* renamed from: e */
    public final int m648e() {
        View m644a = m644a();
        if (m644a == null) {
            return 0;
        }
        return m644a.getPaddingTop();
    }

    @NotNull
    /* renamed from: f */
    public final TextPaint m649f() {
        return (TextPaint) this.f1527a.getValue();
    }

    /* renamed from: g */
    public final int m650g() {
        View m644a = m644a();
        if (m644a == null) {
            return 0;
        }
        return m644a.getMeasuredHeight();
    }

    @Override // android.graphics.drawable.Drawable
    public int getAlpha() {
        return m649f().getAlpha();
    }

    @Override // android.graphics.drawable.Drawable
    @Nullable
    public ColorFilter getColorFilter() {
        return m649f().getColorFilter();
    }

    @Override // android.graphics.drawable.Drawable
    public void getHotspotBounds(@NotNull Rect outRect) {
        Intrinsics.checkNotNullParameter(outRect, "outRect");
        super.getHotspotBounds(outRect);
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return super.getIntrinsicHeight();
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return super.getIntrinsicWidth();
    }

    @Override // android.graphics.drawable.Drawable
    public int getMinimumHeight() {
        return super.getMinimumHeight();
    }

    @Override // android.graphics.drawable.Drawable
    public int getMinimumWidth() {
        return super.getMinimumWidth();
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return getAlpha() < 255 ? -3 : -1;
    }

    /* renamed from: h */
    public final int m651h() {
        View m644a = m644a();
        if (m644a == null) {
            return 0;
        }
        return m644a.getMeasuredWidth();
    }

    @Override // android.graphics.drawable.Drawable
    public boolean isFilterBitmap() {
        return m649f().isFilterBitmap();
    }

    @Override // android.graphics.drawable.Drawable
    @NotNull
    public Drawable mutate() {
        Drawable mutate = super.mutate();
        Intrinsics.checkNotNullExpressionValue(mutate, "super.mutate()");
        return mutate;
    }

    @Override // android.graphics.drawable.Drawable
    public void onBoundsChange(@Nullable Rect bounds) {
        super.onBoundsChange(bounds);
    }

    @Override // android.graphics.drawable.Drawable
    public boolean onLevelChange(int level) {
        return super.onLevelChange(level);
    }

    @Override // android.graphics.drawable.Drawable
    public boolean onStateChange(@Nullable int[] state) {
        return super.onStateChange(state);
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
        if (m649f().getAlpha() != alpha) {
            m649f().setAlpha(alpha);
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void setBounds(int left, int top, int right, int bottom) {
        super.setBounds(left, top, right, bottom);
    }

    @Override // android.graphics.drawable.Drawable
    public void setDither(boolean dither) {
        m649f().setDither(dither);
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setFilterBitmap(boolean filter) {
        m649f().setFilterBitmap(filter);
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setHotspot(float x, float y) {
        super.setHotspot(x, y);
    }

    @Override // android.graphics.drawable.Drawable
    public void setHotspotBounds(int left, int top, int right, int bottom) {
        super.setHotspotBounds(left, top, right, bottom);
    }

    @Override // android.graphics.drawable.Drawable
    public void setTintBlendMode(@Nullable BlendMode blendMode) {
        super.setTintBlendMode(blendMode);
    }

    @Override // android.graphics.drawable.Drawable
    public void setTintList(@Nullable ColorStateList tint) {
        super.setTintList(tint);
    }

    @Override // android.graphics.drawable.Drawable
    public void setTintMode(@Nullable PorterDuff.Mode tintMode) {
        super.setTintMode(tintMode);
    }

    @Override // android.graphics.drawable.Drawable
    public void setBounds(@NotNull Rect bounds) {
        Intrinsics.checkNotNullParameter(bounds, "bounds");
        super.setBounds(bounds);
    }
}
