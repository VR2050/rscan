package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.LinearGradient;
import android.graphics.Matrix;
import android.graphics.Shader;
import android.text.TextPaint;
import android.util.AttributeSet;
import androidx.annotation.ColorInt;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.core.internal.view.SupportMenu;
import com.jbzd.media.movecartoons.R$styleable;
import kotlin.Metadata;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u001f\b\u0007\u0012\b\u0010\u0018\u001a\u0004\u0018\u00010\u0017\u0012\n\b\u0002\u0010\u001a\u001a\u0004\u0018\u00010\u0019¢\u0006\u0004\b\u001b\u0010\u001cJ/\u0010\b\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\b\u0010\tR\u0018\u0010\u000b\u001a\u0004\u0018\u00010\n8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000b\u0010\fR\u0016\u0010\r\u001a\u00020\u00028\u0002@\u0002X\u0083\u000e¢\u0006\u0006\n\u0004\b\r\u0010\u000eR\u0016\u0010\u000f\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000f\u0010\u000eR\u0018\u0010\u0011\u001a\u0004\u0018\u00010\u00108\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0011\u0010\u0012R\u0018\u0010\u0014\u001a\u0004\u0018\u00010\u00138\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0014\u0010\u0015R\u0016\u0010\u0016\u001a\u00020\u00028\u0002@\u0002X\u0083\u000e¢\u0006\u0006\n\u0004\b\u0016\u0010\u000e¨\u0006\u001d"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/GradientTextView;", "Landroidx/appcompat/widget/AppCompatTextView;", "", "w", "h", "oldw", "oldh", "", "onSizeChanged", "(IIII)V", "Landroid/graphics/LinearGradient;", "mLinearGradient", "Landroid/graphics/LinearGradient;", "mStartColor", "I", "mMeasureWidth", "Landroid/text/TextPaint;", "mPaint", "Landroid/text/TextPaint;", "Landroid/graphics/Matrix;", "mTextMatrix", "Landroid/graphics/Matrix;", "mEndColor", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class GradientTextView extends AppCompatTextView {

    @ColorInt
    private int mEndColor;

    @Nullable
    private LinearGradient mLinearGradient;
    private int mMeasureWidth;

    @Nullable
    private TextPaint mPaint;

    @ColorInt
    private int mStartColor;

    @Nullable
    private Matrix mTextMatrix;

    /* JADX WARN: Multi-variable type inference failed */
    @JvmOverloads
    public GradientTextView(@Nullable Context context) {
        this(context, null, 2, 0 == true ? 1 : 0);
    }

    public /* synthetic */ GradientTextView(Context context, AttributeSet attributeSet, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i2 & 2) != 0 ? null : attributeSet);
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Override // android.view.View
    public void onSizeChanged(int w, int h2, int oldw, int oldh) {
        super.onSizeChanged(w, h2, oldw, oldh);
        this.mMeasureWidth = getMeasuredWidth();
        this.mPaint = getPaint();
        LinearGradient linearGradient = new LinearGradient(0.0f, 0.0f, this.mMeasureWidth, 0.0f, new int[]{this.mStartColor, this.mEndColor}, (float[]) null, Shader.TileMode.REPEAT);
        this.mLinearGradient = linearGradient;
        TextPaint textPaint = this.mPaint;
        if (textPaint != null) {
            textPaint.setShader(linearGradient);
        }
        this.mTextMatrix = new Matrix();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public GradientTextView(@Nullable Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNull(context);
        this.mStartColor = SupportMenu.CATEGORY_MASK;
        this.mEndColor = -16776961;
        if (attributeSet != null) {
            TypedArray obtainStyledAttributes = getContext().obtainStyledAttributes(attributeSet, R$styleable.GradientTextView);
            Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "getContext().obtainStyledAttributes(attrs, R.styleable.GradientTextView)");
            this.mStartColor = obtainStyledAttributes.getColor(1, this.mStartColor);
            this.mEndColor = obtainStyledAttributes.getColor(0, this.mEndColor);
        }
    }
}
