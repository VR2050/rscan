package im.uwrkaxlmjj.ui.hviews.helper;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.RectF;
import android.os.Build;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewOutlineProvider;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.lang.ref.WeakReference;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MryLayoutHelper implements MryLayout {
    private int mBorderColor;
    private RectF mBorderRect;
    private int mBorderWidth;
    private int mBottomDividerAlpha;
    private int mBottomDividerColor;
    private int mBottomDividerHeight;
    private int mBottomDividerInsetLeft;
    private int mBottomDividerInsetRight;
    private Paint mClipPaint;
    private Context mContext;
    private Paint mDividerPaint;
    private int mHeightLimit;
    private int mHeightMini;
    private int mHideRadiusSide;
    private boolean mIsOutlineExcludePadding;
    private boolean mIsShowBorderOnlyBeforeL;
    private int mLeftDividerAlpha;
    private int mLeftDividerColor;
    private int mLeftDividerInsetBottom;
    private int mLeftDividerInsetTop;
    private int mLeftDividerWidth;
    private PorterDuffXfermode mMode;
    private int mOuterNormalColor;
    private int mOutlineInsetBottom;
    private int mOutlineInsetLeft;
    private int mOutlineInsetRight;
    private int mOutlineInsetTop;
    private WeakReference<View> mOwner;
    private Path mPath;
    private int mRadius;
    private float[] mRadiusArray;
    private int mRightDividerAlpha;
    private int mRightDividerColor;
    private int mRightDividerInsetBottom;
    private int mRightDividerInsetTop;
    private int mRightDividerWidth;
    private float mShadowAlpha;
    private int mShadowColor;
    private int mShadowElevation;
    private int mTopDividerAlpha;
    private int mTopDividerColor;
    private int mTopDividerHeight;
    private int mTopDividerInsetLeft;
    private int mTopDividerInsetRight;
    private int mWidthLimit;
    private int mWidthMini;

    public MryLayoutHelper(Context context, AttributeSet attrs, int defAttr, View owner) {
        this(context, attrs, defAttr, 0, owner);
    }

    public MryLayoutHelper(Context context, AttributeSet attrs, int defAttr, int defStyleRes, View owner) {
        this.mWidthLimit = 0;
        this.mHeightLimit = 0;
        this.mWidthMini = 0;
        this.mHeightMini = 0;
        this.mTopDividerHeight = 0;
        this.mTopDividerInsetLeft = 0;
        this.mTopDividerInsetRight = 0;
        this.mTopDividerAlpha = 255;
        this.mBottomDividerHeight = 0;
        this.mBottomDividerInsetLeft = 0;
        this.mBottomDividerInsetRight = 0;
        this.mBottomDividerAlpha = 255;
        this.mLeftDividerWidth = 0;
        this.mLeftDividerInsetTop = 0;
        this.mLeftDividerInsetBottom = 0;
        this.mLeftDividerAlpha = 255;
        this.mRightDividerWidth = 0;
        this.mRightDividerInsetTop = 0;
        this.mRightDividerInsetBottom = 0;
        this.mRightDividerAlpha = 255;
        this.mHideRadiusSide = 0;
        this.mBorderColor = 0;
        int i = 1;
        this.mBorderWidth = 1;
        this.mOuterNormalColor = 0;
        this.mIsOutlineExcludePadding = false;
        this.mPath = new Path();
        this.mIsShowBorderOnlyBeforeL = true;
        this.mShadowElevation = 0;
        this.mShadowColor = -10066330;
        this.mOutlineInsetLeft = 0;
        this.mOutlineInsetRight = 0;
        this.mOutlineInsetTop = 0;
        this.mOutlineInsetBottom = 0;
        this.mContext = context;
        this.mOwner = new WeakReference<>(owner);
        int color = Theme.getColor(Theme.key_divider);
        this.mTopDividerColor = color;
        this.mBottomDividerColor = color;
        this.mMode = new PorterDuffXfermode(PorterDuff.Mode.DST_OUT);
        Paint paint = new Paint();
        this.mClipPaint = paint;
        paint.setAntiAlias(true);
        this.mShadowAlpha = MryResHelper.getAttrFloatValue(context, R.style.mryGeneralShadowAlpha);
        this.mBorderRect = new RectF();
        int radius = 0;
        int shadow = 0;
        boolean useThemeGeneralShadowElevation = false;
        if (attrs != null || defAttr != 0 || defStyleRes != 0) {
            TypedArray ta = context.obtainStyledAttributes(attrs, im.uwrkaxlmjj.messenger.R.styleable.MryLayout, defAttr, defStyleRes);
            int count = ta.getIndexCount();
            int i2 = 0;
            while (i2 < count) {
                int index = ta.getIndex(i2);
                if (index == 0) {
                    this.mWidthLimit = ta.getDimensionPixelSize(index, this.mWidthLimit);
                } else if (index == i) {
                    this.mHeightLimit = ta.getDimensionPixelSize(index, this.mHeightLimit);
                } else if (index == 2) {
                    this.mWidthMini = ta.getDimensionPixelSize(index, this.mWidthMini);
                } else if (index == 3) {
                    this.mHeightMini = ta.getDimensionPixelSize(index, this.mHeightMini);
                } else if (index == 30) {
                    this.mTopDividerColor = ta.getColor(index, this.mTopDividerColor);
                } else if (index == 31) {
                    this.mTopDividerHeight = ta.getDimensionPixelSize(index, this.mTopDividerHeight);
                } else if (index == 32) {
                    this.mTopDividerInsetLeft = ta.getDimensionPixelSize(index, this.mTopDividerInsetLeft);
                } else if (index == 33) {
                    this.mTopDividerInsetRight = ta.getDimensionPixelSize(index, this.mTopDividerInsetRight);
                } else if (index == 6) {
                    this.mBottomDividerColor = ta.getColor(index, this.mBottomDividerColor);
                } else if (index == 7) {
                    this.mBottomDividerHeight = ta.getDimensionPixelSize(index, this.mBottomDividerHeight);
                } else if (index == 8) {
                    this.mBottomDividerInsetLeft = ta.getDimensionPixelSize(index, this.mBottomDividerInsetLeft);
                } else if (index == 9) {
                    this.mBottomDividerInsetRight = ta.getDimensionPixelSize(index, this.mBottomDividerInsetRight);
                } else if (index == 11) {
                    this.mLeftDividerColor = ta.getColor(index, this.mLeftDividerColor);
                } else if (index == 14) {
                    this.mLeftDividerWidth = ta.getDimensionPixelSize(index, this.mLeftDividerWidth);
                } else if (index == 13) {
                    this.mLeftDividerInsetTop = ta.getDimensionPixelSize(index, this.mLeftDividerInsetTop);
                } else if (index == 12) {
                    this.mLeftDividerInsetBottom = ta.getDimensionPixelSize(index, this.mLeftDividerInsetBottom);
                } else if (index == 22) {
                    this.mRightDividerColor = ta.getColor(index, this.mRightDividerColor);
                } else if (index == 25) {
                    this.mRightDividerWidth = ta.getDimensionPixelSize(index, this.mRightDividerWidth);
                } else if (index == 24) {
                    this.mRightDividerInsetTop = ta.getDimensionPixelSize(index, this.mRightDividerInsetTop);
                } else if (index == 23) {
                    this.mRightDividerInsetBottom = ta.getDimensionPixelSize(index, this.mRightDividerInsetBottom);
                } else if (index == 4) {
                    this.mBorderColor = ta.getColor(index, this.mBorderColor);
                } else if (index == 5) {
                    this.mBorderWidth = ta.getDimensionPixelSize(index, this.mBorderWidth);
                } else if (index == 21) {
                    radius = ta.getDimensionPixelSize(index, 0);
                } else if (index == 15) {
                    this.mOuterNormalColor = ta.getColor(index, this.mOuterNormalColor);
                } else if (index == 10) {
                    this.mHideRadiusSide = ta.getColor(index, this.mHideRadiusSide);
                } else if (index == 29) {
                    this.mIsShowBorderOnlyBeforeL = ta.getBoolean(index, this.mIsShowBorderOnlyBeforeL);
                } else if (index == 28) {
                    shadow = ta.getDimensionPixelSize(index, shadow);
                } else if (index == 26) {
                    this.mShadowAlpha = ta.getFloat(index, this.mShadowAlpha);
                } else if (index == 27) {
                    this.mShadowColor = ta.getColor(index, -10066330);
                } else if (index == 34) {
                    useThemeGeneralShadowElevation = ta.getBoolean(index, false);
                } else if (index == 18) {
                    this.mOutlineInsetLeft = ta.getDimensionPixelSize(index, 0);
                } else if (index == 19) {
                    this.mOutlineInsetRight = ta.getDimensionPixelSize(index, 0);
                } else if (index == 20) {
                    this.mOutlineInsetTop = ta.getDimensionPixelSize(index, 0);
                } else if (index == 17) {
                    this.mOutlineInsetBottom = ta.getDimensionPixelSize(index, 0);
                } else if (index == 16) {
                    this.mIsOutlineExcludePadding = ta.getBoolean(index, false);
                }
                i2++;
                i = 1;
            }
            ta.recycle();
        }
        if (shadow == 0 && useThemeGeneralShadowElevation) {
            shadow = MryResHelper.getAttrDimen(context, R.style.mryGeneralShadowElevation);
        }
        setRadiusAndShadow(radius, this.mHideRadiusSide, shadow, this.mShadowAlpha);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setUseThemeGeneralShadowElevation() {
        int attrDimen = MryResHelper.getAttrDimen(this.mContext, R.style.mryGeneralShadowElevation);
        this.mShadowElevation = attrDimen;
        setRadiusAndShadow(this.mRadius, this.mHideRadiusSide, attrDimen, this.mShadowAlpha);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setOutlineExcludePadding(boolean outlineExcludePadding) {
        View owner;
        if (!useFeature() || (owner = this.mOwner.get()) == null) {
            return;
        }
        this.mIsOutlineExcludePadding = outlineExcludePadding;
        owner.invalidateOutline();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean setWidthLimit(int widthLimit) {
        if (this.mWidthLimit != widthLimit) {
            this.mWidthLimit = widthLimit;
            return true;
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean setHeightLimit(int heightLimit) {
        if (this.mHeightLimit != heightLimit) {
            this.mHeightLimit = heightLimit;
            return true;
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateLeftSeparatorColor(int color) {
        if (this.mLeftDividerColor != color) {
            this.mLeftDividerColor = color;
            invalidate();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateBottomSeparatorColor(int color) {
        if (this.mBottomDividerColor != color) {
            this.mBottomDividerColor = color;
            invalidate();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateTopSeparatorColor(int color) {
        if (this.mTopDividerColor != color) {
            this.mTopDividerColor = color;
            invalidate();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateRightSeparatorColor(int color) {
        if (this.mRightDividerColor != color) {
            this.mRightDividerColor = color;
            invalidate();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public int getShadowElevation() {
        return this.mShadowElevation;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public float getShadowAlpha() {
        return this.mShadowAlpha;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public int getShadowColor() {
        return this.mShadowColor;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setOutlineInset(int left, int top, int right, int bottom) {
        View owner;
        if (!useFeature() || (owner = this.mOwner.get()) == null) {
            return;
        }
        this.mOutlineInsetLeft = left;
        this.mOutlineInsetRight = right;
        this.mOutlineInsetTop = top;
        this.mOutlineInsetBottom = bottom;
        owner.invalidateOutline();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setShowBorderOnlyBeforeL(boolean showBorderOnlyBeforeL) {
        this.mIsShowBorderOnlyBeforeL = showBorderOnlyBeforeL;
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setShadowElevation(int elevation) {
        if (this.mShadowElevation == elevation) {
            return;
        }
        this.mShadowElevation = elevation;
        invalidateOutline();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setShadowAlpha(float shadowAlpha) {
        if (this.mShadowAlpha == shadowAlpha) {
            return;
        }
        this.mShadowAlpha = shadowAlpha;
        invalidateOutline();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setShadowColor(int shadowColor) {
        if (this.mShadowColor == shadowColor) {
            return;
        }
        this.mShadowColor = shadowColor;
        setShadowColorInner(shadowColor);
    }

    private void setShadowColorInner(int shadowColor) {
        View owner;
        if (Build.VERSION.SDK_INT < 28 || (owner = this.mOwner.get()) == null) {
            return;
        }
        owner.setOutlineAmbientShadowColor(shadowColor);
        owner.setOutlineSpotShadowColor(shadowColor);
    }

    private void invalidateOutline() {
        View owner;
        if (!useFeature() || (owner = this.mOwner.get()) == null) {
            return;
        }
        int i = this.mShadowElevation;
        if (i == 0) {
            owner.setElevation(0.0f);
        } else {
            owner.setElevation(i);
        }
        owner.invalidateOutline();
    }

    private void invalidate() {
        View owner = this.mOwner.get();
        if (owner == null) {
            return;
        }
        owner.invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setHideRadiusSide(int hideRadiusSide) {
        if (this.mHideRadiusSide == hideRadiusSide) {
            return;
        }
        setRadiusAndShadow(this.mRadius, hideRadiusSide, this.mShadowElevation, this.mShadowAlpha);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public int getHideRadiusSide() {
        return this.mHideRadiusSide;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRadius(int radius) {
        if (this.mRadius != radius) {
            setRadiusAndShadow(radius, this.mShadowElevation, this.mShadowAlpha);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRadius(int radius, int hideRadiusSide) {
        if (this.mRadius == radius && hideRadiusSide == this.mHideRadiusSide) {
            return;
        }
        setRadiusAndShadow(radius, hideRadiusSide, this.mShadowElevation, this.mShadowAlpha);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public int getRadius() {
        return this.mRadius;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRadiusAndShadow(int radius, int shadowElevation, float shadowAlpha) {
        setRadiusAndShadow(radius, this.mHideRadiusSide, shadowElevation, shadowAlpha);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRadiusAndShadow(int radius, int hideRadiusSide, int shadowElevation, float shadowAlpha) {
        setRadiusAndShadow(radius, hideRadiusSide, shadowElevation, this.mShadowColor, shadowAlpha);
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRadiusAndShadow(int radius, int hideRadiusSide, int shadowElevation, int shadowColor, float shadowAlpha) {
        View owner = this.mOwner.get();
        if (owner == null) {
            return;
        }
        this.mRadius = radius;
        this.mHideRadiusSide = hideRadiusSide;
        if (radius > 0) {
            if (hideRadiusSide == 1) {
                this.mRadiusArray = new float[]{0.0f, 0.0f, 0.0f, 0.0f, radius, radius, radius, radius};
            } else if (hideRadiusSide == 2) {
                this.mRadiusArray = new float[]{radius, radius, 0.0f, 0.0f, 0.0f, 0.0f, radius, radius};
            } else if (hideRadiusSide == 3) {
                this.mRadiusArray = new float[]{radius, radius, radius, radius, 0.0f, 0.0f, 0.0f, 0.0f};
            } else if (hideRadiusSide == 4) {
                this.mRadiusArray = new float[]{0.0f, 0.0f, radius, radius, radius, radius, 0.0f, 0.0f};
            } else {
                this.mRadiusArray = null;
            }
        }
        this.mShadowElevation = shadowElevation;
        this.mShadowAlpha = shadowAlpha;
        this.mShadowColor = shadowColor;
        if (useFeature()) {
            int i = this.mShadowElevation;
            if (i == 0) {
                owner.setElevation(0.0f);
            } else {
                owner.setElevation(i);
            }
            setShadowColorInner(this.mShadowColor);
            owner.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.hviews.helper.MryLayoutHelper.1
                @Override // android.view.ViewOutlineProvider
                public void getOutline(View view, Outline outline) {
                    float shadowAlpha2;
                    int w = view.getWidth();
                    int h = view.getHeight();
                    if (w == 0 || h == 0) {
                        return;
                    }
                    if (!MryLayoutHelper.this.isRadiusWithSideHidden()) {
                        int top = MryLayoutHelper.this.mOutlineInsetTop;
                        int bottom = Math.max(top + 1, h - MryLayoutHelper.this.mOutlineInsetBottom);
                        int left = MryLayoutHelper.this.mOutlineInsetLeft;
                        int right = w - MryLayoutHelper.this.mOutlineInsetRight;
                        if (MryLayoutHelper.this.mIsOutlineExcludePadding) {
                            left += view.getPaddingLeft();
                            top += view.getPaddingTop();
                            right = Math.max(left + 1, right - view.getPaddingRight());
                            bottom = Math.max(top + 1, bottom - view.getPaddingBottom());
                        }
                        float shadowAlpha3 = MryLayoutHelper.this.mShadowAlpha;
                        if (MryLayoutHelper.this.mShadowElevation != 0) {
                            shadowAlpha2 = shadowAlpha3;
                        } else {
                            shadowAlpha2 = 1.0f;
                        }
                        outline.setAlpha(shadowAlpha2);
                        if (MryLayoutHelper.this.mRadius <= 0) {
                            outline.setRect(left, top, right, bottom);
                            return;
                        }
                        outline.setRoundRect(left, top, right, bottom, MryLayoutHelper.this.mRadius);
                        return;
                    }
                    int left2 = 0;
                    int top2 = 0;
                    int right2 = w;
                    int bottom2 = h;
                    if (MryLayoutHelper.this.mHideRadiusSide != 4) {
                        if (MryLayoutHelper.this.mHideRadiusSide == 1) {
                            top2 = 0 - MryLayoutHelper.this.mRadius;
                        } else if (MryLayoutHelper.this.mHideRadiusSide == 2) {
                            right2 += MryLayoutHelper.this.mRadius;
                        } else if (MryLayoutHelper.this.mHideRadiusSide == 3) {
                            bottom2 += MryLayoutHelper.this.mRadius;
                        }
                    } else {
                        left2 = 0 - MryLayoutHelper.this.mRadius;
                    }
                    outline.setRoundRect(left2, top2, right2, bottom2, MryLayoutHelper.this.mRadius);
                }
            });
            owner.setClipToOutline(this.mRadius > 0);
        }
        owner.invalidate();
    }

    public boolean isRadiusWithSideHidden() {
        return this.mRadius > 0 && this.mHideRadiusSide != 0;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateTopDivider(int topInsetLeft, int topInsetRight, int topDividerHeight, int topDividerColor) {
        this.mTopDividerInsetLeft = topInsetLeft;
        this.mTopDividerInsetRight = topInsetRight;
        this.mTopDividerHeight = topDividerHeight;
        this.mTopDividerColor = topDividerColor;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateBottomDivider(int bottomInsetLeft, int bottomInsetRight, int bottomDividerHeight, int bottomDividerColor) {
        this.mBottomDividerInsetLeft = bottomInsetLeft;
        this.mBottomDividerInsetRight = bottomInsetRight;
        this.mBottomDividerColor = bottomDividerColor;
        this.mBottomDividerHeight = bottomDividerHeight;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateLeftDivider(int leftInsetTop, int leftInsetBottom, int leftDividerWidth, int leftDividerColor) {
        this.mLeftDividerInsetTop = leftInsetTop;
        this.mLeftDividerInsetBottom = leftInsetBottom;
        this.mLeftDividerWidth = leftDividerWidth;
        this.mLeftDividerColor = leftDividerColor;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void updateRightDivider(int rightInsetTop, int rightInsetBottom, int rightDividerWidth, int rightDividerColor) {
        this.mRightDividerInsetTop = rightInsetTop;
        this.mRightDividerInsetBottom = rightInsetBottom;
        this.mRightDividerWidth = rightDividerWidth;
        this.mRightDividerColor = rightDividerColor;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void onlyShowTopDivider(int topInsetLeft, int topInsetRight, int topDividerHeight, int topDividerColor) {
        updateTopDivider(topInsetLeft, topInsetRight, topDividerHeight, topDividerColor);
        this.mLeftDividerWidth = 0;
        this.mRightDividerWidth = 0;
        this.mBottomDividerHeight = 0;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void onlyShowBottomDivider(int bottomInsetLeft, int bottomInsetRight, int bottomDividerHeight, int bottomDividerColor) {
        updateBottomDivider(bottomInsetLeft, bottomInsetRight, bottomDividerHeight, bottomDividerColor);
        this.mLeftDividerWidth = 0;
        this.mRightDividerWidth = 0;
        this.mTopDividerHeight = 0;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void onlyShowLeftDivider(int leftInsetTop, int leftInsetBottom, int leftDividerWidth, int leftDividerColor) {
        updateLeftDivider(leftInsetTop, leftInsetBottom, leftDividerWidth, leftDividerColor);
        this.mRightDividerWidth = 0;
        this.mTopDividerHeight = 0;
        this.mBottomDividerHeight = 0;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void onlyShowRightDivider(int rightInsetTop, int rightInsetBottom, int rightDividerWidth, int rightDividerColor) {
        updateRightDivider(rightInsetTop, rightInsetBottom, rightDividerWidth, rightDividerColor);
        this.mLeftDividerWidth = 0;
        this.mTopDividerHeight = 0;
        this.mBottomDividerHeight = 0;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setTopDividerAlpha(int dividerAlpha) {
        this.mTopDividerAlpha = dividerAlpha;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setBottomDividerAlpha(int dividerAlpha) {
        this.mBottomDividerAlpha = dividerAlpha;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setLeftDividerAlpha(int dividerAlpha) {
        this.mLeftDividerAlpha = dividerAlpha;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setRightDividerAlpha(int dividerAlpha) {
        this.mRightDividerAlpha = dividerAlpha;
    }

    public int handleMiniWidth(int widthMeasureSpec, int measuredWidth) {
        int i;
        if (View.MeasureSpec.getMode(widthMeasureSpec) != 1073741824 && measuredWidth < (i = this.mWidthMini)) {
            return View.MeasureSpec.makeMeasureSpec(i, 1073741824);
        }
        return widthMeasureSpec;
    }

    public int handleMiniHeight(int heightMeasureSpec, int measuredHeight) {
        int i;
        if (View.MeasureSpec.getMode(heightMeasureSpec) != 1073741824 && measuredHeight < (i = this.mHeightMini)) {
            return View.MeasureSpec.makeMeasureSpec(i, 1073741824);
        }
        return heightMeasureSpec;
    }

    public int getMeasuredWidthSpec(int widthMeasureSpec) {
        if (this.mWidthLimit > 0) {
            int size = View.MeasureSpec.getSize(widthMeasureSpec);
            if (size > this.mWidthLimit) {
                int mode = View.MeasureSpec.getMode(widthMeasureSpec);
                if (mode == Integer.MIN_VALUE) {
                    return View.MeasureSpec.makeMeasureSpec(this.mWidthLimit, Integer.MIN_VALUE);
                }
                return View.MeasureSpec.makeMeasureSpec(this.mWidthLimit, 1073741824);
            }
            return widthMeasureSpec;
        }
        return widthMeasureSpec;
    }

    public int getMeasuredHeightSpec(int heightMeasureSpec) {
        if (this.mHeightLimit > 0) {
            int size = View.MeasureSpec.getSize(heightMeasureSpec);
            if (size > this.mHeightLimit) {
                int mode = View.MeasureSpec.getMode(heightMeasureSpec);
                if (mode == Integer.MIN_VALUE) {
                    return View.MeasureSpec.makeMeasureSpec(this.mWidthLimit, Integer.MIN_VALUE);
                }
                return View.MeasureSpec.makeMeasureSpec(this.mWidthLimit, 1073741824);
            }
            return heightMeasureSpec;
        }
        return heightMeasureSpec;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setBorderColor(int borderColor) {
        this.mBorderColor = borderColor;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setBorderWidth(int borderWidth) {
        this.mBorderWidth = borderWidth;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public void setOuterNormalColor(int color) {
        this.mOuterNormalColor = color;
        View owner = this.mOwner.get();
        if (owner != null) {
            owner.invalidate();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean hasTopSeparator() {
        return this.mTopDividerHeight > 0;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean hasRightSeparator() {
        return this.mRightDividerWidth > 0;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean hasBottomSeparator() {
        return this.mBottomDividerHeight > 0;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean hasLeftSeparator() {
        return this.mLeftDividerWidth > 0;
    }

    @Override // im.uwrkaxlmjj.ui.hviews.helper.MryLayout
    public boolean hasBorder() {
        return this.mBorderWidth > 0;
    }

    public void drawDividers(Canvas canvas, int w, int h) {
        View owner = this.mOwner.get();
        if (owner == null) {
            return;
        }
        if (this.mDividerPaint == null && (this.mTopDividerHeight > 0 || this.mBottomDividerHeight > 0 || this.mLeftDividerWidth > 0 || this.mRightDividerWidth > 0)) {
            this.mDividerPaint = new Paint();
        }
        canvas.save();
        canvas.translate(owner.getScrollX(), owner.getScrollY());
        int i = this.mTopDividerHeight;
        if (i > 0) {
            this.mDividerPaint.setStrokeWidth(i);
            this.mDividerPaint.setColor(this.mTopDividerColor);
            int i2 = this.mTopDividerAlpha;
            if (i2 < 255) {
                this.mDividerPaint.setAlpha(i2);
            }
            float y = (this.mTopDividerHeight * 1.0f) / 2.0f;
            canvas.drawLine(this.mTopDividerInsetLeft, y, w - this.mTopDividerInsetRight, y, this.mDividerPaint);
        }
        int i3 = this.mBottomDividerHeight;
        if (i3 > 0) {
            this.mDividerPaint.setStrokeWidth(i3);
            this.mDividerPaint.setColor(this.mBottomDividerColor);
            int i4 = this.mBottomDividerAlpha;
            if (i4 < 255) {
                this.mDividerPaint.setAlpha(i4);
            }
            float y2 = (float) Math.floor(h - ((this.mBottomDividerHeight * 1.0f) / 2.0f));
            canvas.drawLine(this.mBottomDividerInsetLeft, y2, w - this.mBottomDividerInsetRight, y2, this.mDividerPaint);
        }
        int i5 = this.mLeftDividerWidth;
        if (i5 > 0) {
            this.mDividerPaint.setStrokeWidth(i5);
            this.mDividerPaint.setColor(this.mLeftDividerColor);
            int i6 = this.mLeftDividerAlpha;
            if (i6 < 255) {
                this.mDividerPaint.setAlpha(i6);
            }
            canvas.drawLine(0.0f, this.mLeftDividerInsetTop, 0.0f, h - this.mLeftDividerInsetBottom, this.mDividerPaint);
        }
        int i7 = this.mRightDividerWidth;
        if (i7 > 0) {
            this.mDividerPaint.setStrokeWidth(i7);
            this.mDividerPaint.setColor(this.mRightDividerColor);
            int i8 = this.mRightDividerAlpha;
            if (i8 < 255) {
                this.mDividerPaint.setAlpha(i8);
            }
            canvas.drawLine(w, this.mRightDividerInsetTop, w, h - this.mRightDividerInsetBottom, this.mDividerPaint);
        }
        canvas.restore();
    }

    public void dispatchRoundBorderDraw(Canvas canvas) {
        View owner = this.mOwner.get();
        if (owner == null) {
            return;
        }
        boolean needCheckFakeOuterNormalDraw = (this.mRadius <= 0 || useFeature() || this.mOuterNormalColor == 0) ? false : true;
        boolean needDrawBorder = this.mBorderWidth > 0 && this.mBorderColor != 0;
        if (!needCheckFakeOuterNormalDraw && !needDrawBorder) {
            return;
        }
        if (this.mIsShowBorderOnlyBeforeL && useFeature() && this.mShadowElevation != 0) {
            return;
        }
        int width = canvas.getWidth();
        int height = canvas.getHeight();
        canvas.save();
        canvas.translate(owner.getScrollX(), owner.getScrollY());
        if (this.mIsOutlineExcludePadding) {
            this.mBorderRect.set(owner.getPaddingLeft(), owner.getPaddingTop(), width - owner.getPaddingRight(), height - owner.getPaddingBottom());
        } else {
            this.mBorderRect.set(0.0f, 0.0f, width, height);
        }
        if (needCheckFakeOuterNormalDraw) {
            int layerId = canvas.saveLayer(0.0f, 0.0f, width, height, null, 31);
            canvas.drawColor(this.mOuterNormalColor);
            this.mClipPaint.setColor(this.mOuterNormalColor);
            this.mClipPaint.setStyle(Paint.Style.FILL);
            this.mClipPaint.setXfermode(this.mMode);
            float[] fArr = this.mRadiusArray;
            if (fArr == null) {
                RectF rectF = this.mBorderRect;
                int i = this.mRadius;
                canvas.drawRoundRect(rectF, i, i, this.mClipPaint);
            } else {
                drawRoundRect(canvas, this.mBorderRect, fArr, this.mClipPaint);
            }
            this.mClipPaint.setXfermode(null);
            canvas.restoreToCount(layerId);
        }
        if (needDrawBorder) {
            this.mClipPaint.setColor(this.mBorderColor);
            this.mClipPaint.setStrokeWidth(this.mBorderWidth);
            this.mClipPaint.setStyle(Paint.Style.STROKE);
            float[] fArr2 = this.mRadiusArray;
            if (fArr2 != null) {
                drawRoundRect(canvas, this.mBorderRect, fArr2, this.mClipPaint);
            } else {
                int i2 = this.mRadius;
                if (i2 <= 0) {
                    canvas.drawRect(this.mBorderRect, this.mClipPaint);
                } else {
                    canvas.drawRoundRect(this.mBorderRect, i2, i2, this.mClipPaint);
                }
            }
        }
        canvas.restore();
    }

    private void drawRoundRect(Canvas canvas, RectF rect, float[] radiusArray, Paint paint) {
        this.mPath.reset();
        this.mPath.addRoundRect(rect, radiusArray, Path.Direction.CW);
        canvas.drawPath(this.mPath, paint);
    }

    public static boolean useFeature() {
        return Build.VERSION.SDK_INT >= 21;
    }
}
