package com.qunidayede.supportlibrary.widget;

import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.LinearInterpolator;
import com.qunidayede.supportlibrary.R$attr;
import com.qunidayede.supportlibrary.R$styleable;
import com.qunidayede.supportlibrary.widget.LoadingView;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.p146l.C1568e;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u0011\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B'\b\u0007\u0012\u0006\u0010*\u001a\u00020)\u0012\n\b\u0002\u0010,\u001a\u0004\u0018\u00010+\u0012\b\b\u0002\u0010-\u001a\u00020\u000b¢\u0006\u0004\b.\u0010/J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\u0007\u001a\u00020\u0004H\u0014¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0004H\u0014¢\u0006\u0004\b\t\u0010\bJ\u001f\u0010\r\u001a\u00020\u00042\u0006\u0010\n\u001a\u00020\u00012\u0006\u0010\f\u001a\u00020\u000bH\u0014¢\u0006\u0004\b\r\u0010\u000eJ\u0015\u0010\u0010\u001a\u00020\u00042\u0006\u0010\u000f\u001a\u00020\u000b¢\u0006\u0004\b\u0010\u0010\u0011J\u000f\u0010\u0012\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0012\u0010\bJ\u000f\u0010\u0013\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0013\u0010\bR\u0016\u0010\u0016\u001a\u00020\u000b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0014\u0010\u0015R\u0016\u0010\u0018\u001a\u00020\u000b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0017\u0010\u0015R\u0016\u0010\u001a\u001a\u00020\u000b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0019\u0010\u0015R\u0016\u0010\u001c\u001a\u00020\u000b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001b\u0010\u0015R\u0018\u0010 \u001a\u0004\u0018\u00010\u001d8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001e\u0010\u001fR\u0016\u0010$\u001a\u00020!8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\"\u0010#R\u0018\u0010(\u001a\u0004\u0018\u00010%8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b&\u0010'¨\u00060"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/widget/LoadingView;", "Landroid/view/View;", "Landroid/graphics/Canvas;", "canvas", "", "onDraw", "(Landroid/graphics/Canvas;)V", "onAttachedToWindow", "()V", "onDetachedFromWindow", "changedView", "", "visibility", "onVisibilityChanged", "(Landroid/view/View;I)V", "loadColor", "setLoadColor", "(I)V", "a", "b", "h", "I", "mAnimateValue", C1568e.f1949a, "mLoadColor", "f", "mLoadSize", "g", "mLoadDuration", "Landroid/graphics/Paint;", "i", "Landroid/graphics/Paint;", "mPaint", "Landroid/animation/ValueAnimator$AnimatorUpdateListener;", "k", "Landroid/animation/ValueAnimator$AnimatorUpdateListener;", "updateListener", "Landroid/animation/ValueAnimator;", "j", "Landroid/animation/ValueAnimator;", "mValueAnimator", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "defaultStyle", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class LoadingView extends View {

    /* renamed from: c */
    public static final /* synthetic */ int f10366c = 0;

    /* renamed from: e, reason: from kotlin metadata */
    public int mLoadColor;

    /* renamed from: f, reason: from kotlin metadata */
    public int mLoadSize;

    /* renamed from: g, reason: from kotlin metadata */
    public int mLoadDuration;

    /* renamed from: h, reason: from kotlin metadata */
    public int mAnimateValue;

    /* renamed from: i, reason: from kotlin metadata */
    @Nullable
    public Paint mPaint;

    /* renamed from: j, reason: from kotlin metadata */
    @Nullable
    public ValueAnimator mValueAnimator;

    /* renamed from: k, reason: from kotlin metadata */
    @NotNull
    public final ValueAnimator.AnimatorUpdateListener updateListener;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public LoadingView(@NotNull Context context) {
        this(context, null, R$attr.loading_view_style);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* renamed from: a */
    public final void m4579a() {
        if (this.mValueAnimator == null) {
            ValueAnimator ofInt = ValueAnimator.ofInt(0, 7);
            ofInt.setDuration(this.mLoadDuration);
            ofInt.setRepeatMode(1);
            ofInt.setRepeatCount(-1);
            ofInt.setInterpolator(new LinearInterpolator());
            ofInt.addUpdateListener(this.updateListener);
            Unit unit = Unit.INSTANCE;
            this.mValueAnimator = ofInt;
        }
        ValueAnimator valueAnimator = this.mValueAnimator;
        Intrinsics.checkNotNull(valueAnimator);
        if (valueAnimator.isStarted()) {
            return;
        }
        ValueAnimator valueAnimator2 = this.mValueAnimator;
        Intrinsics.checkNotNull(valueAnimator2);
        valueAnimator2.start();
    }

    /* renamed from: b */
    public final void m4580b() {
        ValueAnimator valueAnimator = this.mValueAnimator;
        if (valueAnimator != null) {
            Intrinsics.checkNotNull(valueAnimator);
            if (valueAnimator.isStarted()) {
                ValueAnimator valueAnimator2 = this.mValueAnimator;
                Intrinsics.checkNotNull(valueAnimator2);
                valueAnimator2.removeUpdateListener(this.updateListener);
                ValueAnimator valueAnimator3 = this.mValueAnimator;
                Intrinsics.checkNotNull(valueAnimator3);
                valueAnimator3.removeAllUpdateListeners();
                ValueAnimator valueAnimator4 = this.mValueAnimator;
                Intrinsics.checkNotNull(valueAnimator4);
                valueAnimator4.cancel();
                this.mValueAnimator = null;
            }
        }
    }

    @Override // android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        m4579a();
    }

    @Override // android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        m4580b();
    }

    @Override // android.view.View
    public void onDraw(@NotNull Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        super.onDraw(canvas);
        int saveLayer = canvas.saveLayer(0.0f, 0.0f, getWidth(), getHeight(), null);
        int i2 = this.mAnimateValue * 45;
        int i3 = this.mLoadSize / 4;
        int width = getWidth() / 2;
        Paint paint = this.mPaint;
        if (paint != null) {
            paint.setStrokeWidth(i3 / 2);
        }
        float f2 = width;
        canvas.rotate(i2, f2, f2);
        canvas.translate(f2, f2);
        int i4 = 0;
        while (true) {
            int i5 = i4 + 1;
            canvas.rotate(45.0f);
            int i6 = i3 / 2;
            canvas.translate(0.0f, ((-this.mLoadSize) / 2) + i6);
            Paint paint2 = this.mPaint;
            Intrinsics.checkNotNull(paint2);
            canvas.drawCircle(0.0f, 0.0f, (float) (((i4 + 7) * i3) / 28.0d), paint2);
            canvas.translate(0.0f, (this.mLoadSize / 2) - i6);
            if (i5 >= 8) {
                canvas.restoreToCount(saveLayer);
                return;
            }
            i4 = i5;
        }
    }

    @Override // android.view.View
    public void onVisibilityChanged(@NotNull View changedView, int visibility) {
        Intrinsics.checkNotNullParameter(changedView, "changedView");
        super.onVisibilityChanged(changedView, visibility);
        if (visibility == 0) {
            m4579a();
        } else {
            m4580b();
        }
    }

    public final void setLoadColor(int loadColor) {
        this.mLoadColor = loadColor;
        Paint paint = this.mPaint;
        if (paint != null) {
            paint.setColor(loadColor);
        }
        invalidate();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public LoadingView(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, R$attr.loading_view_style);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public LoadingView(@NotNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNullParameter(context, "context");
        this.mLoadDuration = 800;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.LoadingView, R$attr.loading_view_style, 0);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttributes(\n            attrs, R.styleable.LoadingView, R.attr.loading_view_style, 0\n        )");
        this.mLoadColor = obtainStyledAttributes.getColor(R$styleable.LoadingView_loading_view_color, -1);
        this.mLoadSize = obtainStyledAttributes.getDimensionPixelSize(R$styleable.LoadingView_loading_view_size, C4195m.m4785R(32.0f));
        this.mLoadDuration = obtainStyledAttributes.getInteger(R$styleable.LoadingView_loading_view_duration, this.mLoadDuration);
        obtainStyledAttributes.recycle();
        Paint paint = new Paint();
        paint.setColor(this.mLoadColor);
        paint.setAntiAlias(true);
        paint.setStrokeCap(Paint.Cap.BUTT);
        Unit unit = Unit.INSTANCE;
        this.mPaint = paint;
        this.updateListener = new ValueAnimator.AnimatorUpdateListener() { // from class: b.w.b.e.a
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator animation) {
                LoadingView this$0 = LoadingView.this;
                int i3 = LoadingView.f10366c;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.checkNotNullParameter(animation, "animation");
                Object animatedValue = animation.getAnimatedValue();
                Objects.requireNonNull(animatedValue, "null cannot be cast to non-null type kotlin.Int");
                this$0.mAnimateValue = ((Integer) animatedValue).intValue();
                this$0.invalidate();
            }
        };
    }
}
