package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.util.AttributeSet;
import im.uwrkaxlmjj.messenger.R;

/* JADX INFO: loaded from: classes5.dex */
public class MryRoundButtonDrawable extends GradientDrawable {
    private ColorStateList mFillColors;
    private ColorStateList mStrokeColors;
    private boolean mRadiusAdjustBounds = true;
    private int mStrokeWidth = 0;

    public void setBgData(ColorStateList colors) {
        int currentColor;
        if (hasNativeStateListAPI()) {
            super.setColor(colors);
            return;
        }
        this.mFillColors = colors;
        if (colors == null) {
            currentColor = 0;
        } else {
            currentColor = colors.getColorForState(getState(), 0);
        }
        setColor(currentColor);
    }

    public void setStrokeData(int width, ColorStateList colors) {
        int currentColor;
        this.mStrokeWidth = width;
        this.mStrokeColors = colors;
        if (hasNativeStateListAPI()) {
            super.setStroke(width, colors);
            return;
        }
        if (colors == null) {
            currentColor = 0;
        } else {
            currentColor = colors.getColorForState(getState(), 0);
        }
        setStroke(width, currentColor);
    }

    public int getStrokeWidth() {
        return this.mStrokeWidth;
    }

    public void setStrokeWidth(int width) {
        setStrokeData(width, this.mStrokeColors);
    }

    public void setStrokeColors(ColorStateList colors) {
        setStrokeData(this.mStrokeWidth, colors);
    }

    private boolean hasNativeStateListAPI() {
        return Build.VERSION.SDK_INT >= 21;
    }

    public void setIsRadiusAdjustBounds(boolean isRadiusAdjustBounds) {
        this.mRadiusAdjustBounds = isRadiusAdjustBounds;
    }

    @Override // android.graphics.drawable.GradientDrawable, android.graphics.drawable.Drawable
    protected boolean onStateChange(int[] stateSet) {
        boolean superRet = super.onStateChange(stateSet);
        ColorStateList colorStateList = this.mFillColors;
        if (colorStateList != null) {
            int color = colorStateList.getColorForState(stateSet, 0);
            setColor(color);
            superRet = true;
        }
        ColorStateList colorStateList2 = this.mStrokeColors;
        if (colorStateList2 != null) {
            int color2 = colorStateList2.getColorForState(stateSet, 0);
            setStroke(this.mStrokeWidth, color2);
            return true;
        }
        return superRet;
    }

    @Override // android.graphics.drawable.GradientDrawable, android.graphics.drawable.Drawable
    public boolean isStateful() {
        ColorStateList colorStateList;
        ColorStateList colorStateList2 = this.mFillColors;
        return (colorStateList2 != null && colorStateList2.isStateful()) || ((colorStateList = this.mStrokeColors) != null && colorStateList.isStateful()) || super.isStateful();
    }

    @Override // android.graphics.drawable.GradientDrawable, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect r) {
        super.onBoundsChange(r);
        if (this.mRadiusAdjustBounds) {
            setCornerRadius(Math.min(r.width(), r.height()) / 2);
        }
    }

    public static MryRoundButtonDrawable fromAttributeSet(Context context, AttributeSet attrs, int defStyleAttr) {
        TypedArray typedArray = context.obtainStyledAttributes(attrs, R.styleable.MryRoundButton, defStyleAttr, 0);
        ColorStateList colorBg = typedArray.getColorStateList(0);
        ColorStateList colorBorder = typedArray.getColorStateList(1);
        int borderWidth = typedArray.getDimensionPixelSize(2, 0);
        boolean isRadiusAdjustBounds = typedArray.getBoolean(4, false);
        int mRadius = typedArray.getDimensionPixelSize(5, 0);
        int mRadiusTopLeft = typedArray.getDimensionPixelSize(8, 0);
        int mRadiusTopRight = typedArray.getDimensionPixelSize(9, 0);
        int mRadiusBottomLeft = typedArray.getDimensionPixelSize(6, 0);
        int mRadiusBottomRight = typedArray.getDimensionPixelSize(7, 0);
        typedArray.recycle();
        MryRoundButtonDrawable bg = new MryRoundButtonDrawable();
        bg.setBgData(colorBg);
        bg.setStrokeData(borderWidth, colorBorder);
        if (mRadiusTopLeft <= 0 && mRadiusTopRight <= 0 && mRadiusBottomLeft <= 0 && mRadiusBottomRight <= 0) {
            bg.setCornerRadius(mRadius);
            if (mRadius > 0) {
                isRadiusAdjustBounds = false;
            }
        } else {
            float[] radii = {mRadiusTopLeft, mRadiusTopLeft, mRadiusTopRight, mRadiusTopRight, mRadiusBottomRight, mRadiusBottomRight, mRadiusBottomLeft, mRadiusBottomLeft};
            bg.setCornerRadii(radii);
            isRadiusAdjustBounds = false;
        }
        bg.setIsRadiusAdjustBounds(isRadiusAdjustBounds);
        return bg;
    }
}
