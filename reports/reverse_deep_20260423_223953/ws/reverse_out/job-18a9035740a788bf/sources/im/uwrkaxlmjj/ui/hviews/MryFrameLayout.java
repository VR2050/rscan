package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.graphics.Canvas;
import android.util.AttributeSet;
import im.uwrkaxlmjj.ui.hviews.helper.MryLayout;
import im.uwrkaxlmjj.ui.hviews.helper.MryLayoutHelper;

/* JADX INFO: loaded from: classes5.dex */
public class MryFrameLayout extends MryAlphaFrameLayout implements MryLayout {
    private MryLayoutHelper mLayoutHelper;

    public MryFrameLayout(Context context) {
        super(context);
        init(context, null, 0);
    }

    public MryFrameLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
        init(context, attrs, 0);
    }

    public MryFrameLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context, attrs, defStyleAttr);
    }

    private void init(Context context, AttributeSet attrs, int defStyleAttr) {
        this.mLayoutHelper = new MryLayoutHelper(context, attrs, defStyleAttr, this);
        setChangeAlphaWhenDisable(false);
        setChangeAlphaWhenPress(false);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int widthMeasureSpec2 = this.mLayoutHelper.getMeasuredWidthSpec(widthMeasureSpec);
        int heightMeasureSpec2 = this.mLayoutHelper.getMeasuredHeightSpec(heightMeasureSpec);
        super.onMeasure(widthMeasureSpec2, heightMeasureSpec2);
        int minW = this.mLayoutHelper.handleMiniWidth(widthMeasureSpec2, getMeasuredWidth());
        int minH = this.mLayoutHelper.handleMiniHeight(heightMeasureSpec2, getMeasuredHeight());
        if (widthMeasureSpec2 != minW || heightMeasureSpec2 != minH) {
            super.onMeasure(minW, minH);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateTopDivider(int topInsetLeft, int topInsetRight, int topDividerHeight, int topDividerColor) {
        this.mLayoutHelper.updateTopDivider(topInsetLeft, topInsetRight, topDividerHeight, topDividerColor);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateBottomDivider(int bottomInsetLeft, int bottomInsetRight, int bottomDividerHeight, int bottomDividerColor) {
        this.mLayoutHelper.updateBottomDivider(bottomInsetLeft, bottomInsetRight, bottomDividerHeight, bottomDividerColor);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateLeftDivider(int leftInsetTop, int leftInsetBottom, int leftDividerWidth, int leftDividerColor) {
        this.mLayoutHelper.updateLeftDivider(leftInsetTop, leftInsetBottom, leftDividerWidth, leftDividerColor);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateRightDivider(int rightInsetTop, int rightInsetBottom, int rightDividerWidth, int rightDividerColor) {
        this.mLayoutHelper.updateRightDivider(rightInsetTop, rightInsetBottom, rightDividerWidth, rightDividerColor);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void onlyShowTopDivider(int topInsetLeft, int topInsetRight, int topDividerHeight, int topDividerColor) {
        this.mLayoutHelper.onlyShowTopDivider(topInsetLeft, topInsetRight, topDividerHeight, topDividerColor);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void onlyShowBottomDivider(int bottomInsetLeft, int bottomInsetRight, int bottomDividerHeight, int bottomDividerColor) {
        this.mLayoutHelper.onlyShowBottomDivider(bottomInsetLeft, bottomInsetRight, bottomDividerHeight, bottomDividerColor);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void onlyShowLeftDivider(int leftInsetTop, int leftInsetBottom, int leftDividerWidth, int leftDividerColor) {
        this.mLayoutHelper.onlyShowLeftDivider(leftInsetTop, leftInsetBottom, leftDividerWidth, leftDividerColor);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void onlyShowRightDivider(int rightInsetTop, int rightInsetBottom, int rightDividerWidth, int rightDividerColor) {
        this.mLayoutHelper.onlyShowRightDivider(rightInsetTop, rightInsetBottom, rightDividerWidth, rightDividerColor);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setTopDividerAlpha(int dividerAlpha) {
        this.mLayoutHelper.setTopDividerAlpha(dividerAlpha);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setBottomDividerAlpha(int dividerAlpha) {
        this.mLayoutHelper.setBottomDividerAlpha(dividerAlpha);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setLeftDividerAlpha(int dividerAlpha) {
        this.mLayoutHelper.setLeftDividerAlpha(dividerAlpha);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRightDividerAlpha(int dividerAlpha) {
        this.mLayoutHelper.setRightDividerAlpha(dividerAlpha);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRadiusAndShadow(int radius, int shadowElevation, float shadowAlpha) {
        this.mLayoutHelper.setRadiusAndShadow(radius, shadowElevation, shadowAlpha);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRadiusAndShadow(int radius, int hideRadiusSide, int shadowElevation, float shadowAlpha) {
        this.mLayoutHelper.setRadiusAndShadow(radius, hideRadiusSide, shadowElevation, shadowAlpha);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRadiusAndShadow(int radius, int hideRadiusSide, int shadowElevation, int shadowColor, float shadowAlpha) {
        this.mLayoutHelper.setRadiusAndShadow(radius, hideRadiusSide, shadowElevation, shadowColor, shadowAlpha);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRadius(int radius) {
        this.mLayoutHelper.setRadius(radius);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRadius(int radius, int hideRadiusSide) {
        this.mLayoutHelper.setRadius(radius, hideRadiusSide);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public int getRadius() {
        return this.mLayoutHelper.getRadius();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setOutlineInset(int left, int top, int right, int bottom) {
        this.mLayoutHelper.setOutlineInset(left, top, right, bottom);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setHideRadiusSide(int hideRadiusSide) {
        this.mLayoutHelper.setHideRadiusSide(hideRadiusSide);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public int getHideRadiusSide() {
        return this.mLayoutHelper.getHideRadiusSide();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setBorderColor(int borderColor) {
        this.mLayoutHelper.setBorderColor(borderColor);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setBorderWidth(int borderWidth) {
        this.mLayoutHelper.setBorderWidth(borderWidth);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setShowBorderOnlyBeforeL(boolean showBorderOnlyBeforeL) {
        this.mLayoutHelper.setShowBorderOnlyBeforeL(showBorderOnlyBeforeL);
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean setWidthLimit(int widthLimit) {
        if (this.mLayoutHelper.setWidthLimit(widthLimit)) {
            requestLayout();
            invalidate();
            return true;
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean setHeightLimit(int heightLimit) {
        if (this.mLayoutHelper.setHeightLimit(heightLimit)) {
            requestLayout();
            invalidate();
            return true;
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setUseThemeGeneralShadowElevation() {
        this.mLayoutHelper.setUseThemeGeneralShadowElevation();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setOutlineExcludePadding(boolean outlineExcludePadding) {
        this.mLayoutHelper.setOutlineExcludePadding(outlineExcludePadding);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setShadowElevation(int elevation) {
        this.mLayoutHelper.setShadowElevation(elevation);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public int getShadowElevation() {
        return this.mLayoutHelper.getShadowElevation();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setShadowAlpha(float shadowAlpha) {
        this.mLayoutHelper.setShadowAlpha(shadowAlpha);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public float getShadowAlpha() {
        return this.mLayoutHelper.getShadowAlpha();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setShadowColor(int shadowColor) {
        this.mLayoutHelper.setShadowColor(shadowColor);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public int getShadowColor() {
        return this.mLayoutHelper.getShadowColor();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setOuterNormalColor(int color) {
        this.mLayoutHelper.setOuterNormalColor(color);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateBottomSeparatorColor(int color) {
        this.mLayoutHelper.updateBottomSeparatorColor(color);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateLeftSeparatorColor(int color) {
        this.mLayoutHelper.updateLeftSeparatorColor(color);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateRightSeparatorColor(int color) {
        this.mLayoutHelper.updateRightSeparatorColor(color);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateTopSeparatorColor(int color) {
        this.mLayoutHelper.updateTopSeparatorColor(color);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void dispatchDraw(Canvas canvas) {
        super.dispatchDraw(canvas);
        this.mLayoutHelper.drawDividers(canvas, getWidth(), getHeight());
        this.mLayoutHelper.dispatchRoundBorderDraw(canvas);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean hasBorder() {
        return this.mLayoutHelper.hasBorder();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean hasLeftSeparator() {
        return this.mLayoutHelper.hasLeftSeparator();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean hasTopSeparator() {
        return this.mLayoutHelper.hasTopSeparator();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean hasRightSeparator() {
        return this.mLayoutHelper.hasRightSeparator();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean hasBottomSeparator() {
        return this.mLayoutHelper.hasBottomSeparator();
    }
}
