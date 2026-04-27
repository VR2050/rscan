package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.view.View;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.components.WallpaperParallaxEffect;

/* JADX INFO: loaded from: classes5.dex */
public class SizeNotifierFrameLayout extends FrameLayout {
    private Drawable backgroundDrawable;
    private int bottomClip;
    private SizeNotifierFrameLayoutDelegate delegate;
    private int keyboardHeight;
    private boolean occupyStatusBar;
    private WallpaperParallaxEffect parallaxEffect;
    private float parallaxScale;
    private boolean paused;
    private android.graphics.Rect rect;
    private float translationX;
    private float translationY;

    public interface SizeNotifierFrameLayoutDelegate {
        void onSizeChanged(int i, boolean z);
    }

    public SizeNotifierFrameLayout(Context context) {
        super(context);
        this.rect = new android.graphics.Rect();
        this.occupyStatusBar = true;
        this.parallaxScale = 1.0f;
        this.paused = true;
        setWillNotDraw(false);
    }

    public void setBackgroundImage(Drawable bitmap, boolean motion) {
        this.backgroundDrawable = bitmap;
        if (motion) {
            if (this.parallaxEffect == null) {
                WallpaperParallaxEffect wallpaperParallaxEffect = new WallpaperParallaxEffect(getContext());
                this.parallaxEffect = wallpaperParallaxEffect;
                wallpaperParallaxEffect.setCallback(new WallpaperParallaxEffect.Callback() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$SizeNotifierFrameLayout$hRPmQ25DB4fwuQFOu3vaLh7V_MY
                    @Override // im.uwrkaxlmjj.ui.components.WallpaperParallaxEffect.Callback
                    public final void onOffsetsChanged(int i, int i2) {
                        this.f$0.lambda$setBackgroundImage$0$SizeNotifierFrameLayout(i, i2);
                    }
                });
                if (getMeasuredWidth() != 0 && getMeasuredHeight() != 0) {
                    this.parallaxScale = this.parallaxEffect.getScale(getMeasuredWidth(), getMeasuredHeight());
                }
            }
            if (!this.paused) {
                this.parallaxEffect.setEnabled(true);
            }
        } else {
            WallpaperParallaxEffect wallpaperParallaxEffect2 = this.parallaxEffect;
            if (wallpaperParallaxEffect2 != null) {
                wallpaperParallaxEffect2.setEnabled(false);
                this.parallaxEffect = null;
                this.parallaxScale = 1.0f;
                this.translationX = 0.0f;
                this.translationY = 0.0f;
            }
        }
        invalidate();
    }

    public /* synthetic */ void lambda$setBackgroundImage$0$SizeNotifierFrameLayout(int offsetX, int offsetY) {
        this.translationX = offsetX;
        this.translationY = offsetY;
        invalidate();
    }

    public Drawable getBackgroundImage() {
        return this.backgroundDrawable;
    }

    public void setDelegate(SizeNotifierFrameLayoutDelegate delegate) {
        this.delegate = delegate;
    }

    public void setOccupyStatusBar(boolean value) {
        this.occupyStatusBar = value;
    }

    public void onPause() {
        WallpaperParallaxEffect wallpaperParallaxEffect = this.parallaxEffect;
        if (wallpaperParallaxEffect != null) {
            wallpaperParallaxEffect.setEnabled(false);
        }
        this.paused = true;
    }

    public void onResume() {
        WallpaperParallaxEffect wallpaperParallaxEffect = this.parallaxEffect;
        if (wallpaperParallaxEffect != null) {
            wallpaperParallaxEffect.setEnabled(true);
        }
        this.paused = false;
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
        super.onLayout(changed, l, t, r, b);
        notifyHeightChanged();
    }

    public int getKeyboardHeight() {
        View rootView = getRootView();
        getWindowVisibleDisplayFrame(this.rect);
        if (this.rect.bottom == 0 && this.rect.top == 0) {
            return 0;
        }
        int usableViewHeight = (rootView.getHeight() - (this.rect.top != 0 ? AndroidUtilities.statusBarHeight : 0)) - AndroidUtilities.getViewInset(rootView);
        return Math.max(0, usableViewHeight - (this.rect.bottom - this.rect.top));
    }

    public void notifyHeightChanged() {
        WallpaperParallaxEffect wallpaperParallaxEffect = this.parallaxEffect;
        if (wallpaperParallaxEffect != null) {
            this.parallaxScale = wallpaperParallaxEffect.getScale(getMeasuredWidth(), getMeasuredHeight());
        }
        if (this.delegate != null) {
            this.keyboardHeight = getKeyboardHeight();
            final boolean isWidthGreater = AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y;
            post(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$SizeNotifierFrameLayout$BL63By1g6k11gSQq4WWu227_e60
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$notifyHeightChanged$1$SizeNotifierFrameLayout(isWidthGreater);
                }
            });
        }
    }

    public /* synthetic */ void lambda$notifyHeightChanged$1$SizeNotifierFrameLayout(boolean isWidthGreater) {
        SizeNotifierFrameLayoutDelegate sizeNotifierFrameLayoutDelegate = this.delegate;
        if (sizeNotifierFrameLayoutDelegate != null) {
            sizeNotifierFrameLayoutDelegate.onSizeChanged(this.keyboardHeight, isWidthGreater);
        }
    }

    public void setBottomClip(int value) {
        this.bottomClip = value;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        Drawable drawable = this.backgroundDrawable;
        if (drawable != null) {
            if ((drawable instanceof ColorDrawable) || (drawable instanceof GradientDrawable)) {
                if (this.bottomClip != 0) {
                    canvas.save();
                    canvas.clipRect(0, 0, getMeasuredWidth(), getMeasuredHeight() - this.bottomClip);
                }
                this.backgroundDrawable.setBounds(0, 0, getMeasuredWidth(), getMeasuredHeight());
                this.backgroundDrawable.draw(canvas);
                if (this.bottomClip != 0) {
                    canvas.restore();
                    return;
                }
                return;
            }
            if (drawable instanceof BitmapDrawable) {
                BitmapDrawable bitmapDrawable = (BitmapDrawable) drawable;
                if (bitmapDrawable.getTileModeX() == Shader.TileMode.REPEAT) {
                    canvas.save();
                    float scale = 2.0f / AndroidUtilities.density;
                    canvas.scale(scale, scale);
                    this.backgroundDrawable.setBounds(0, 0, (int) Math.ceil(getMeasuredWidth() / scale), (int) Math.ceil(getMeasuredHeight() / scale));
                    this.backgroundDrawable.draw(canvas);
                    canvas.restore();
                    return;
                }
                int actionBarHeight = (isActionBarVisible() ? ActionBar.getCurrentActionBarHeight() : 0) + ((Build.VERSION.SDK_INT < 21 || !this.occupyStatusBar) ? 0 : AndroidUtilities.statusBarHeight);
                int viewHeight = getMeasuredHeight() - actionBarHeight;
                float scaleX = getMeasuredWidth() / this.backgroundDrawable.getIntrinsicWidth();
                float scaleY = (this.keyboardHeight + viewHeight) / this.backgroundDrawable.getIntrinsicHeight();
                float scale2 = scaleX < scaleY ? scaleY : scaleX;
                int width = (int) Math.ceil(this.backgroundDrawable.getIntrinsicWidth() * scale2 * this.parallaxScale);
                int height = (int) Math.ceil(this.backgroundDrawable.getIntrinsicHeight() * scale2 * this.parallaxScale);
                int x = ((getMeasuredWidth() - width) / 2) + ((int) this.translationX);
                int y = (((viewHeight - height) + this.keyboardHeight) / 2) + actionBarHeight + ((int) this.translationY);
                canvas.save();
                canvas.clipRect(0, actionBarHeight, width, getMeasuredHeight() - this.bottomClip);
                this.backgroundDrawable.setAlpha(255);
                this.backgroundDrawable.setBounds(x, y, x + width, y + height);
                this.backgroundDrawable.draw(canvas);
                canvas.restore();
                return;
            }
            return;
        }
        super.onDraw(canvas);
    }

    protected boolean isActionBarVisible() {
        return true;
    }
}
