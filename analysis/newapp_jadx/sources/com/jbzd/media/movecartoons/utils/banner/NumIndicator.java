package com.jbzd.media.movecartoons.utils.banner;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import com.youth.banner.indicator.BaseIndicator;
import com.youth.banner.util.BannerUtils;
import kotlin.Metadata;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.p146l.C1568e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B)\b\u0007\u0012\b\u0010\u0014\u001a\u0004\u0018\u00010\u0013\u0012\n\b\u0002\u0010\u0016\u001a\u0004\u0018\u00010\u0015\u0012\b\b\u0002\u0010\u0017\u001a\u00020\u0002¢\u0006\u0004\b\u0018\u0010\u0019J\u001f\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0006\u0010\u0007J\u0017\u0010\n\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\bH\u0014¢\u0006\u0004\b\n\u0010\u000bR\u0016\u0010\u000e\u001a\u00020\u00028\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\f\u0010\rR\u0016\u0010\u0010\u001a\u00020\u00028\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u000f\u0010\rR\u0016\u0010\u0012\u001a\u00020\u00028\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0011\u0010\r¨\u0006\u001a"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/utils/banner/NumIndicator;", "Lcom/youth/banner/indicator/BaseIndicator;", "", "widthMeasureSpec", "heightMeasureSpec", "", "onMeasure", "(II)V", "Landroid/graphics/Canvas;", "canvas", "onDraw", "(Landroid/graphics/Canvas;)V", C1568e.f1949a, "I", "_height", "c", "_width", "f", "radius", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "defStyleAttr", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class NumIndicator extends BaseIndicator {

    /* renamed from: c, reason: from kotlin metadata */
    public final int _width;

    /* renamed from: e, reason: from kotlin metadata */
    public final int _height;

    /* renamed from: f, reason: from kotlin metadata */
    public final int radius;

    @JvmOverloads
    public NumIndicator(@Nullable Context context) {
        this(context, null, 0);
    }

    @Override // android.view.View
    public void onDraw(@NotNull Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        super.onDraw(canvas);
        int indicatorSize = this.config.getIndicatorSize();
        if (indicatorSize <= 1) {
            return;
        }
        RectF rectF = new RectF(0.0f, 0.0f, this._width, this._height);
        this.mPaint.setColor(Color.parseColor("#70000000"));
        int i2 = this.radius;
        canvas.drawRoundRect(rectF, i2, i2, this.mPaint);
        StringBuilder sb = new StringBuilder();
        sb.append(this.config.getCurrentPosition() + 1);
        sb.append('/');
        sb.append(indicatorSize);
        String sb2 = sb.toString();
        this.mPaint.setColor(-1);
        canvas.drawText(sb2, this._width / 2, (float) (this._height * 0.7d), this.mPaint);
    }

    @Override // android.view.View
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        if (this.config.getIndicatorSize() <= 1) {
            return;
        }
        setMeasuredDimension(this._width, this._height);
    }

    @JvmOverloads
    public NumIndicator(@Nullable Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    @JvmOverloads
    public NumIndicator(@Nullable Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.mPaint.setTextSize(BannerUtils.dp2px(14.0f));
        this.mPaint.setTextAlign(Paint.Align.CENTER);
        this._width = BannerUtils.dp2px(48.0f);
        this._height = BannerUtils.dp2px(24.0f);
        this.radius = BannerUtils.dp2px(12.0f);
    }
}
