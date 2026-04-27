package im.uwrkaxlmjj.ui.actionbar;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Property;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.view.animation.Interpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.core.view.NestedScrollingParent;
import androidx.core.view.NestedScrollingParentHelper;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.ui.components.AnimationProperties;
import im.uwrkaxlmjj.ui.components.CubicBezierInterpolator;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class BottomSheet extends Dialog {
    private boolean allowCustomAnimation;
    private boolean allowDrawContent;
    private boolean allowNestedScroll;
    protected boolean applyBottomPadding;
    protected boolean applyTopPadding;
    protected ColorDrawable backDrawable;
    protected int backgroundPaddingLeft;
    protected int backgroundPaddingTop;
    protected ContainerView container;
    protected ViewGroup containerView;
    protected int currentAccount;
    protected AnimatorSet currentSheetAnimation;
    protected int currentSheetAnimationType;
    private View customView;
    private BottomSheetDelegateInterface delegate;
    private boolean dimBehind;
    private Runnable dismissRunnable;
    private boolean dismissed;
    private boolean focusable;
    protected boolean fullWidth;
    public boolean isAnimationed;
    protected boolean isFullscreen;
    private int[] itemIcons;
    private ArrayList<BottomSheetCell> itemViews;
    private CharSequence[] items;
    private WindowInsets lastInsets;
    private int layoutCount;
    protected boolean mblnCanScroll;
    protected View nestedScrollChild;
    private DialogInterface.OnClickListener onClickListener;
    protected Interpolator openInterpolator;
    protected Drawable shadowDrawable;
    private boolean showWithoutAnimation;
    private Runnable startAnimationRunnable;
    private int tag;
    private CharSequence title;
    private TextView titleView;
    private int touchSlop;
    private boolean useFastDismiss;
    private boolean useHardwareLayer;

    public interface BottomSheetDelegateInterface {
        boolean canDismiss();

        void onOpenAnimationEnd();

        void onOpenAnimationStart();
    }

    static /* synthetic */ int access$710(BottomSheet x0) {
        int i = x0.layoutCount;
        x0.layoutCount = i - 1;
        return i;
    }

    public Runnable getDismissRunnable() {
        return this.dismissRunnable;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public class ContainerView extends FrameLayout implements NestedScrollingParent {
        private AnimatorSet currentAnimation;
        private boolean maybeStartTracking;
        private NestedScrollingParentHelper nestedScrollingParentHelper;
        private boolean startedTracking;
        private int startedTrackingPointerId;
        private int startedTrackingX;
        private int startedTrackingY;
        private VelocityTracker velocityTracker;

        public ContainerView(Context context) {
            super(context);
            this.velocityTracker = null;
            this.startedTrackingPointerId = -1;
            this.maybeStartTracking = false;
            this.startedTracking = false;
            this.currentAnimation = null;
            this.nestedScrollingParentHelper = new NestedScrollingParentHelper(this);
        }

        @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
        public boolean onStartNestedScroll(View child, View target, int nestedScrollAxes) {
            return (BottomSheet.this.nestedScrollChild == null || child == BottomSheet.this.nestedScrollChild) && !BottomSheet.this.dismissed && BottomSheet.this.allowNestedScroll && nestedScrollAxes == 2 && !BottomSheet.this.canDismissWithSwipe();
        }

        @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
        public void onNestedScrollAccepted(View child, View target, int nestedScrollAxes) {
            this.nestedScrollingParentHelper.onNestedScrollAccepted(child, target, nestedScrollAxes);
            if (BottomSheet.this.dismissed || !BottomSheet.this.allowNestedScroll) {
                return;
            }
            cancelCurrentAnimation();
        }

        @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
        public void onStopNestedScroll(View target) {
            this.nestedScrollingParentHelper.onStopNestedScroll(target);
            if (BottomSheet.this.dismissed || !BottomSheet.this.allowNestedScroll) {
                return;
            }
            BottomSheet.this.containerView.getTranslationY();
            if (BottomSheet.this.canDismissWithSwipe()) {
                checkDismiss(0.0f, 0.0f);
            }
        }

        @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
        public void onNestedScroll(View target, int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed) {
            if (BottomSheet.this.dismissed || !BottomSheet.this.allowNestedScroll) {
                return;
            }
            cancelCurrentAnimation();
            if (dyUnconsumed != 0) {
                float currentTranslation = BottomSheet.this.containerView.getTranslationY() - dyUnconsumed;
                if (currentTranslation < 0.0f) {
                    currentTranslation = 0.0f;
                }
                if (BottomSheet.this.mblnCanScroll) {
                    BottomSheet.this.containerView.setTranslationY(currentTranslation);
                }
            }
        }

        @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
        public void onNestedPreScroll(View target, int dx, int dy, int[] consumed) {
            if (BottomSheet.this.dismissed || !BottomSheet.this.allowNestedScroll) {
                return;
            }
            cancelCurrentAnimation();
            float currentTranslation = BottomSheet.this.containerView.getTranslationY();
            if (currentTranslation > 0.0f && dy > 0) {
                float currentTranslation2 = currentTranslation - dy;
                consumed[1] = dy;
                if (currentTranslation2 < 0.0f) {
                    currentTranslation2 = 0.0f;
                }
                if (BottomSheet.this.mblnCanScroll) {
                    BottomSheet.this.containerView.setTranslationY(currentTranslation2);
                }
            }
        }

        @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
        public boolean onNestedFling(View target, float velocityX, float velocityY, boolean consumed) {
            return false;
        }

        @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
        public boolean onNestedPreFling(View target, float velocityX, float velocityY) {
            return false;
        }

        @Override // android.view.ViewGroup, androidx.core.view.NestedScrollingParent
        public int getNestedScrollAxes() {
            return this.nestedScrollingParentHelper.getNestedScrollAxes();
        }

        private void checkDismiss(float velX, float velY) {
            float translationY = BottomSheet.this.containerView.getTranslationY();
            boolean backAnimation = (translationY < AndroidUtilities.getPixelsInCM(0.8f, false) && (velY < 3500.0f || Math.abs(velY) < Math.abs(velX))) || (velY < 0.0f && Math.abs(velY) >= 3500.0f);
            if (!backAnimation) {
                boolean allowOld = BottomSheet.this.allowCustomAnimation;
                BottomSheet.this.allowCustomAnimation = false;
                BottomSheet.this.useFastDismiss = true;
                BottomSheet.this.dismiss();
                BottomSheet.this.allowCustomAnimation = allowOld;
                return;
            }
            AnimatorSet animatorSet = new AnimatorSet();
            this.currentAnimation = animatorSet;
            animatorSet.playTogether(ObjectAnimator.ofFloat(BottomSheet.this.containerView, "translationY", 0.0f));
            this.currentAnimation.setDuration((int) ((translationY / AndroidUtilities.getPixelsInCM(0.8f, false)) * 150.0f));
            this.currentAnimation.setInterpolator(CubicBezierInterpolator.EASE_OUT);
            this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.BottomSheet.ContainerView.1
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (ContainerView.this.currentAnimation != null && ContainerView.this.currentAnimation.equals(animation)) {
                        ContainerView.this.currentAnimation = null;
                    }
                    NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 512);
                }
            });
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 512);
            this.currentAnimation.start();
        }

        private void cancelCurrentAnimation() {
            AnimatorSet animatorSet = this.currentAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.currentAnimation = null;
            }
        }

        boolean processTouchEvent(MotionEvent ev, boolean intercept) {
            if (BottomSheet.this.dismissed) {
                return false;
            }
            if (BottomSheet.this.onContainerTouchEvent(ev)) {
                return true;
            }
            if (BottomSheet.this.canDismissWithTouchOutside() && ev != null && ((ev.getAction() == 0 || ev.getAction() == 2) && !this.startedTracking && !this.maybeStartTracking && ev.getPointerCount() == 1)) {
                this.startedTrackingX = (int) ev.getX();
                int y = (int) ev.getY();
                this.startedTrackingY = y;
                if (y < BottomSheet.this.containerView.getTop() || this.startedTrackingX < BottomSheet.this.containerView.getLeft() || this.startedTrackingX > BottomSheet.this.containerView.getRight()) {
                    BottomSheet.this.dismiss();
                    return true;
                }
                this.startedTrackingPointerId = ev.getPointerId(0);
                this.maybeStartTracking = true;
                cancelCurrentAnimation();
                VelocityTracker velocityTracker = this.velocityTracker;
                if (velocityTracker != null) {
                    velocityTracker.clear();
                }
            } else if (ev != null && ev.getAction() == 2 && ev.getPointerId(0) == this.startedTrackingPointerId && BottomSheet.this.canDismissWithSwipe()) {
                if (this.velocityTracker == null) {
                    this.velocityTracker = VelocityTracker.obtain();
                }
                float dx = Math.abs((int) (ev.getX() - this.startedTrackingX));
                float dy = ((int) ev.getY()) - this.startedTrackingY;
                this.velocityTracker.addMovement(ev);
                if (this.maybeStartTracking && !this.startedTracking && dy > 0.0f && dy / 3.0f > Math.abs(dx) && Math.abs(dy) >= BottomSheet.this.touchSlop) {
                    this.startedTrackingY = (int) ev.getY();
                    this.maybeStartTracking = false;
                    this.startedTracking = true;
                    requestDisallowInterceptTouchEvent(true);
                } else if (this.startedTracking) {
                    float translationY = BottomSheet.this.containerView.getTranslationY();
                    float translationY2 = translationY + dy;
                    if (translationY2 < 0.0f) {
                        translationY2 = 0.0f;
                    }
                    BottomSheet.this.containerView.setTranslationY(translationY2);
                    this.startedTrackingY = (int) ev.getY();
                }
            } else if (ev == null || (ev != null && ev.getPointerId(0) == this.startedTrackingPointerId && (ev.getAction() == 3 || ev.getAction() == 1 || ev.getAction() == 6))) {
                if (this.velocityTracker == null) {
                    this.velocityTracker = VelocityTracker.obtain();
                }
                this.velocityTracker.computeCurrentVelocity(1000);
                float translationY3 = BottomSheet.this.containerView.getTranslationY();
                if (this.startedTracking || translationY3 != 0.0f) {
                    checkDismiss(this.velocityTracker.getXVelocity(), this.velocityTracker.getYVelocity());
                    this.startedTracking = false;
                } else {
                    this.maybeStartTracking = false;
                    this.startedTracking = false;
                }
                VelocityTracker velocityTracker2 = this.velocityTracker;
                if (velocityTracker2 != null) {
                    velocityTracker2.recycle();
                    this.velocityTracker = null;
                }
                this.startedTrackingPointerId = -1;
            }
            return (!intercept && this.maybeStartTracking) || this.startedTracking || !BottomSheet.this.canDismissWithSwipe();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent ev) {
            return processTouchEvent(ev, false);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int widthSpec;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int height = View.MeasureSpec.getSize(heightMeasureSpec);
            if (BottomSheet.this.lastInsets != null && Build.VERSION.SDK_INT >= 21) {
                height -= BottomSheet.this.lastInsets.getSystemWindowInsetBottom();
            }
            setMeasuredDimension(width, height);
            if (BottomSheet.this.lastInsets != null && Build.VERSION.SDK_INT >= 21) {
                width -= BottomSheet.this.lastInsets.getSystemWindowInsetRight() + BottomSheet.this.lastInsets.getSystemWindowInsetLeft();
            }
            boolean isPortrait = width < height;
            if (BottomSheet.this.containerView != null) {
                if (!BottomSheet.this.fullWidth) {
                    if (AndroidUtilities.isTablet()) {
                        widthSpec = View.MeasureSpec.makeMeasureSpec(((int) (Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) * 0.8f)) + (BottomSheet.this.backgroundPaddingLeft * 2), 1073741824);
                    } else {
                        widthSpec = View.MeasureSpec.makeMeasureSpec(isPortrait ? (BottomSheet.this.backgroundPaddingLeft * 2) + width : ((int) Math.max(width * 0.8f, Math.min(AndroidUtilities.dp(480.0f), width))) + (BottomSheet.this.backgroundPaddingLeft * 2), 1073741824);
                    }
                    BottomSheet.this.containerView.measure(widthSpec, View.MeasureSpec.makeMeasureSpec(height, Integer.MIN_VALUE));
                } else {
                    BottomSheet.this.containerView.measure(View.MeasureSpec.makeMeasureSpec((BottomSheet.this.backgroundPaddingLeft * 2) + width, 1073741824), View.MeasureSpec.makeMeasureSpec(height, Integer.MIN_VALUE));
                }
            }
            int childCount = getChildCount();
            for (int i = 0; i < childCount; i++) {
                View child = getChildAt(i);
                if (child.getVisibility() != 8 && child != BottomSheet.this.containerView && !BottomSheet.this.onCustomMeasure(child, width, height)) {
                    measureChildWithMargins(child, View.MeasureSpec.makeMeasureSpec(width, 1073741824), 0, View.MeasureSpec.makeMeasureSpec(height, 1073741824), 0);
                }
            }
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            int left2;
            int right2;
            int childLeft;
            int childTop;
            int left3;
            int right3;
            BottomSheet.access$710(BottomSheet.this);
            int i = 21;
            if (BottomSheet.this.containerView != null) {
                if (BottomSheet.this.lastInsets != null && Build.VERSION.SDK_INT >= 21) {
                    left3 = left + BottomSheet.this.lastInsets.getSystemWindowInsetLeft();
                    right3 = right - BottomSheet.this.lastInsets.getSystemWindowInsetRight();
                } else {
                    left3 = left;
                    right3 = right;
                }
                int t = (bottom - top) - BottomSheet.this.containerView.getMeasuredHeight();
                int l = ((right3 - left3) - BottomSheet.this.containerView.getMeasuredWidth()) / 2;
                if (BottomSheet.this.lastInsets != null && Build.VERSION.SDK_INT >= 21) {
                    l += BottomSheet.this.lastInsets.getSystemWindowInsetLeft();
                }
                BottomSheet.this.containerView.layout(l, t, BottomSheet.this.containerView.getMeasuredWidth() + l, BottomSheet.this.containerView.getMeasuredHeight() + t);
                left2 = left3;
                right2 = right3;
            } else {
                left2 = left;
                right2 = right;
            }
            int count = getChildCount();
            int i2 = 0;
            while (i2 < count) {
                View child = getChildAt(i2);
                if (child.getVisibility() != 8 && child != BottomSheet.this.containerView && !BottomSheet.this.onCustomLayout(child, left2, top, right2, bottom)) {
                    FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) child.getLayoutParams();
                    int width = child.getMeasuredWidth();
                    int height = child.getMeasuredHeight();
                    int gravity = lp.gravity;
                    if (gravity == -1) {
                        gravity = 51;
                    }
                    int absoluteGravity = gravity & 7;
                    int verticalGravity = gravity & 112;
                    int i3 = absoluteGravity & 7;
                    if (i3 == 1) {
                        int childLeft2 = right2 - left2;
                        childLeft = (((childLeft2 - width) / 2) + lp.leftMargin) - lp.rightMargin;
                    } else if (i3 == 5) {
                        int childLeft3 = right2 - width;
                        childLeft = childLeft3 - lp.rightMargin;
                    } else {
                        childLeft = lp.leftMargin;
                    }
                    if (verticalGravity == 16) {
                        int childTop2 = bottom - top;
                        childTop = (((childTop2 - height) / 2) + lp.topMargin) - lp.bottomMargin;
                    } else if (verticalGravity != 48 && verticalGravity == 80) {
                        int childTop3 = bottom - top;
                        childTop = (childTop3 - height) - lp.bottomMargin;
                    } else {
                        childTop = lp.topMargin;
                    }
                    if (BottomSheet.this.lastInsets != null && Build.VERSION.SDK_INT >= i) {
                        childLeft += BottomSheet.this.lastInsets.getSystemWindowInsetLeft();
                    }
                    child.layout(childLeft, childTop, childLeft + width, childTop + height);
                }
                i2++;
                i = 21;
            }
            if (BottomSheet.this.layoutCount == 0 && BottomSheet.this.startAnimationRunnable != null) {
                AndroidUtilities.cancelRunOnUIThread(BottomSheet.this.startAnimationRunnable);
                BottomSheet.this.startAnimationRunnable.run();
                BottomSheet.this.startAnimationRunnable = null;
            }
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent event) {
            if (BottomSheet.this.canDismissWithSwipe()) {
                return processTouchEvent(event, true);
            }
            return super.onInterceptTouchEvent(event);
        }

        @Override // android.view.ViewGroup, android.view.ViewParent
        public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
            if (this.maybeStartTracking && !this.startedTracking) {
                onTouchEvent(null);
            }
            super.requestDisallowInterceptTouchEvent(disallowIntercept);
        }

        @Override // android.view.View
        public boolean hasOverlappingRendering() {
            return false;
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            BottomSheet.this.onContainerDraw(canvas);
        }
    }

    public static class BottomSheetDelegate implements BottomSheetDelegateInterface {
        @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet.BottomSheetDelegateInterface
        public void onOpenAnimationStart() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet.BottomSheetDelegateInterface
        public void onOpenAnimationEnd() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet.BottomSheetDelegateInterface
        public boolean canDismiss() {
            return true;
        }
    }

    public static class BottomSheetCell extends FrameLayout {
        private ImageView imageView;
        private TextView textView;

        public BottomSheetCell(Context context, int type) {
            super(context);
            setBackground(null);
            setBackgroundDrawable(Theme.getSelectorDrawable(false));
            ImageView imageView = new ImageView(context);
            this.imageView = imageView;
            imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogIcon), PorterDuff.Mode.MULTIPLY));
            addView(this.imageView, LayoutHelper.createFrame(56, 48, (LocaleController.isRTL ? 5 : 3) | 16));
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setLines(1);
            this.textView.setSingleLine(true);
            this.textView.setGravity(1);
            this.textView.setEllipsize(TextUtils.TruncateAt.END);
            if (type == 0) {
                this.textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
                this.textView.setTextSize(1, 16.0f);
                addView(this.textView, LayoutHelper.createFrame(-2, -2, (LocaleController.isRTL ? 5 : 3) | 16));
            } else if (type == 1) {
                this.textView.setGravity(17);
                this.textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
                this.textView.setTextSize(1, 14.0f);
                this.textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                addView(this.textView, LayoutHelper.createFrame(-1, -1.0f));
            }
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(48.0f), 1073741824));
        }

        public void setTextColor(int color) {
            this.textView.setTextColor(color);
        }

        public void setGravity(int gravity) {
            this.textView.setGravity(gravity);
        }

        public void setTextAndIcon(CharSequence text, int icon) {
            this.textView.setText(text);
            if (icon != 0) {
                this.imageView.setImageResource(icon);
                this.imageView.setVisibility(0);
                this.textView.setPadding(AndroidUtilities.dp(LocaleController.isRTL ? 16.0f : 72.0f), 0, AndroidUtilities.dp(LocaleController.isRTL ? 72.0f : 16.0f), 0);
            } else {
                this.imageView.setVisibility(4);
                this.textView.setPadding(AndroidUtilities.dp(16.0f), 0, AndroidUtilities.dp(16.0f), 0);
            }
        }
    }

    @Override // android.app.Dialog, android.view.Window.Callback
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
    }

    public void setAllowNestedScroll(boolean value) {
        this.allowNestedScroll = value;
        if (!value) {
            this.containerView.setTranslationY(0.0f);
        }
    }

    public BottomSheet(Context context, int themeResId) {
        super(context, themeResId);
        this.currentAccount = UserConfig.selectedAccount;
        this.allowDrawContent = true;
        this.useHardwareLayer = true;
        this.mblnCanScroll = true;
        this.backDrawable = new ColorDrawable(-16777216);
        this.allowCustomAnimation = true;
        this.openInterpolator = CubicBezierInterpolator.EASE_OUT_QUINT;
        this.dimBehind = true;
        this.allowNestedScroll = true;
        this.applyTopPadding = true;
        this.applyBottomPadding = true;
        this.itemViews = new ArrayList<>();
        this.dismissRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$PtIFe8fJfUfijuPu7Scv85Hevp4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.dismiss();
            }
        };
    }

    public BottomSheet(Context context, boolean needFocus, int backgroundType) {
        super(context, R.plurals.TransparentDialog);
        this.currentAccount = UserConfig.selectedAccount;
        this.allowDrawContent = true;
        this.useHardwareLayer = true;
        this.mblnCanScroll = true;
        this.backDrawable = new ColorDrawable(-16777216);
        this.allowCustomAnimation = true;
        this.openInterpolator = CubicBezierInterpolator.EASE_OUT_QUINT;
        this.dimBehind = true;
        this.allowNestedScroll = true;
        this.applyTopPadding = true;
        this.applyBottomPadding = true;
        this.itemViews = new ArrayList<>();
        this.dismissRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$PtIFe8fJfUfijuPu7Scv85Hevp4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.dismiss();
            }
        };
        init(context, needFocus, backgroundType);
    }

    protected void init(Context context, boolean needFocus, int backgroundType) {
        if (Build.VERSION.SDK_INT >= 21) {
            getWindow().addFlags(-2147417856);
        }
        ViewConfiguration vc = ViewConfiguration.get(context);
        this.touchSlop = vc.getScaledTouchSlop();
        Rect padding = new Rect();
        if (backgroundType == 0) {
            Drawable drawableMutate = context.getResources().getDrawable(R.drawable.sheet_shadow).mutate();
            this.shadowDrawable = drawableMutate;
            drawableMutate.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogBackground), PorterDuff.Mode.MULTIPLY));
        } else if (backgroundType == 1) {
            Drawable drawableMutate2 = context.getResources().getDrawable(R.drawable.sheet_shadow_round).mutate();
            this.shadowDrawable = drawableMutate2;
            drawableMutate2.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogBackground), PorterDuff.Mode.MULTIPLY));
        } else if (backgroundType == 2) {
            this.shadowDrawable = new ColorDrawable(0);
        }
        this.shadowDrawable.getPadding(padding);
        this.backgroundPaddingLeft = padding.left;
        this.backgroundPaddingTop = padding.top;
        ContainerView containerView = new ContainerView(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.BottomSheet.1
            @Override // android.view.ViewGroup
            public boolean drawChild(Canvas canvas, View child, long drawingTime) {
                try {
                    if (BottomSheet.this.allowDrawContent) {
                        if (super.drawChild(canvas, child, drawingTime)) {
                            return true;
                        }
                    }
                    return false;
                } catch (Exception e) {
                    FileLog.e(e);
                    return true;
                }
            }
        };
        this.container = containerView;
        containerView.setBackgroundDrawable(this.backDrawable);
        this.focusable = needFocus;
        if (Build.VERSION.SDK_INT >= 21) {
            this.container.setFitsSystemWindows(true);
            this.container.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$BottomSheet$mgUSlUaAmC4oV_UvtPNIHmIPJxw
                @Override // android.view.View.OnApplyWindowInsetsListener
                public final WindowInsets onApplyWindowInsets(View view, WindowInsets windowInsets) {
                    return this.f$0.lambda$init$0$BottomSheet(view, windowInsets);
                }
            });
            this.container.setSystemUiVisibility(1280);
        }
        this.backDrawable.setAlpha(0);
    }

    public /* synthetic */ WindowInsets lambda$init$0$BottomSheet(View v, WindowInsets insets) {
        this.lastInsets = insets;
        v.requestLayout();
        return insets.consumeSystemWindowInsets();
    }

    @Override // android.app.Dialog
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Window window = getWindow();
        window.setWindowAnimations(R.plurals.DialogNoAnimation);
        setContentView(this.container, new ViewGroup.LayoutParams(-1, -1));
        int i = 0;
        if (this.containerView == null) {
            FrameLayout frameLayout = new FrameLayout(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.BottomSheet.2
                @Override // android.view.View
                public boolean hasOverlappingRendering() {
                    return false;
                }

                @Override // android.view.View
                public void setTranslationY(float translationY) {
                    super.setTranslationY(translationY);
                    BottomSheet.this.onContainerTranslationYChanged(translationY);
                }
            };
            this.containerView = frameLayout;
            frameLayout.setBackgroundDrawable(this.shadowDrawable);
            this.containerView.setPadding(this.backgroundPaddingLeft, ((this.applyTopPadding ? AndroidUtilities.dp(8.0f) : 0) + this.backgroundPaddingTop) - 1, this.backgroundPaddingLeft, this.applyBottomPadding ? AndroidUtilities.dp(8.0f) : 0);
        }
        this.containerView.setVisibility(4);
        this.container.addView(this.containerView, 0, LayoutHelper.createFrame(-1, -2, 80));
        int topOffset = 0;
        if (this.title != null) {
            TextView textView = new TextView(getContext());
            this.titleView = textView;
            textView.setLines(1);
            this.titleView.setSingleLine(true);
            this.titleView.setText(this.title);
            this.titleView.setTextColor(Theme.getColor(Theme.key_dialogTextGray2));
            this.titleView.setTextSize(1, 16.0f);
            this.titleView.setEllipsize(TextUtils.TruncateAt.MIDDLE);
            this.titleView.setPadding(AndroidUtilities.dp(16.0f), 0, AndroidUtilities.dp(16.0f), AndroidUtilities.dp(8.0f));
            this.titleView.setGravity(16);
            this.containerView.addView(this.titleView, LayoutHelper.createFrame(-1, 48.0f));
            this.titleView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$BottomSheet$m3-0uZ2Q6OswGf1lO-xnXa2MNz4
                @Override // android.view.View.OnTouchListener
                public final boolean onTouch(View view, MotionEvent motionEvent) {
                    return BottomSheet.lambda$onCreate$1(view, motionEvent);
                }
            });
            topOffset = 0 + 48;
        }
        View view = this.customView;
        if (view != null) {
            if (view.getParent() != null) {
                ViewGroup viewGroup = (ViewGroup) this.customView.getParent();
                viewGroup.removeView(this.customView);
            }
            ViewGroup viewGroup2 = this.containerView;
            viewGroup2.addView(this.customView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 0.0f, topOffset, 0.0f, 0.0f));
        } else if (this.items != null) {
            int a = 0;
            while (true) {
                CharSequence[] charSequenceArr = this.items;
                if (a >= charSequenceArr.length) {
                    break;
                }
                if (charSequenceArr[a] != null) {
                    BottomSheetCell cell = new BottomSheetCell(getContext(), i);
                    CharSequence charSequence = this.items[a];
                    int[] iArr = this.itemIcons;
                    cell.setTextAndIcon(charSequence, iArr != null ? iArr[a] : 0);
                    this.containerView.addView(cell, LayoutHelper.createFrame(-1.0f, 48.0f, 51, 0.0f, topOffset, 0.0f, 0.0f));
                    topOffset += 48;
                    cell.setTag(Integer.valueOf(a));
                    cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$BottomSheet$S-e9T2O42hFG_lcc1Od0lehSwPU
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view2) {
                            this.f$0.lambda$onCreate$2$BottomSheet(view2);
                        }
                    });
                    this.itemViews.add(cell);
                }
                a++;
                i = 0;
            }
        }
        WindowManager.LayoutParams params = window.getAttributes();
        params.width = -1;
        params.gravity = 51;
        params.dimAmount = 0.0f;
        params.flags &= -3;
        if (this.focusable) {
            params.softInputMode = 16;
        } else {
            params.flags |= 131072;
        }
        if (this.isFullscreen) {
            if (Build.VERSION.SDK_INT >= 21) {
                params.flags |= -2147417856;
            }
            params.flags |= 1024;
            this.container.setSystemUiVisibility(1284);
        }
        params.height = -1;
        if (Build.VERSION.SDK_INT >= 28) {
            params.layoutInDisplayCutoutMode = 1;
        }
        window.setAttributes(params);
    }

    static /* synthetic */ boolean lambda$onCreate$1(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$onCreate$2$BottomSheet(View v) {
        dismissWithButtonClick(((Integer) v.getTag()).intValue());
    }

    public boolean isFocusable() {
        return this.focusable;
    }

    public void setFocusable(boolean value) {
        if (this.focusable == value) {
            return;
        }
        this.focusable = value;
        Window window = getWindow();
        WindowManager.LayoutParams params = window.getAttributes();
        if (this.focusable) {
            params.softInputMode = 16;
            params.flags &= -131073;
        } else {
            params.softInputMode = 48;
            params.flags |= 131072;
        }
        window.setAttributes(params);
    }

    public void setShowWithoutAnimation(boolean value) {
        this.showWithoutAnimation = value;
    }

    public void setBackgroundColor(int color) {
        this.shadowDrawable.setColorFilter(color, PorterDuff.Mode.MULTIPLY);
    }

    @Override // android.app.Dialog
    public void show() {
        super.show();
        if (this.focusable) {
            getWindow().setSoftInputMode(16);
        }
        this.dismissed = false;
        cancelSheetAnimation();
        this.containerView.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.displaySize.x + (this.backgroundPaddingLeft * 2), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.displaySize.y, Integer.MIN_VALUE));
        if (!this.showWithoutAnimation) {
            this.backDrawable.setAlpha(0);
            if (Build.VERSION.SDK_INT >= 18) {
                this.layoutCount = 2;
                this.containerView.setTranslationY(r0.getMeasuredHeight());
                Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.BottomSheet.3
                    @Override // java.lang.Runnable
                    public void run() {
                        if (BottomSheet.this.startAnimationRunnable == this && !BottomSheet.this.dismissed) {
                            BottomSheet.this.startAnimationRunnable = null;
                            BottomSheet.this.startOpenAnimation();
                        }
                    }
                };
                this.startAnimationRunnable = runnable;
                AndroidUtilities.runOnUIThread(runnable, 150L);
                return;
            }
            startOpenAnimation();
            return;
        }
        this.backDrawable.setAlpha(this.dimBehind ? 51 : 0);
        this.containerView.setTranslationY(0.0f);
    }

    public void setAllowDrawContent(boolean value) {
        if (this.allowDrawContent != value) {
            this.allowDrawContent = value;
            this.container.setBackgroundDrawable(value ? this.backDrawable : null);
            this.container.invalidate();
        }
    }

    protected boolean canDismissWithSwipe() {
        return true;
    }

    protected boolean onContainerTouchEvent(MotionEvent event) {
        return false;
    }

    public void setCustomView(View view) {
        this.customView = view;
    }

    @Override // android.app.Dialog
    public void setTitle(CharSequence value) {
        this.title = value;
    }

    public void setApplyTopPadding(boolean value) {
        this.applyTopPadding = value;
    }

    public void setApplyBottomPadding(boolean value) {
        this.applyBottomPadding = value;
    }

    protected boolean onCustomMeasure(View view, int width, int height) {
        return false;
    }

    protected boolean onCustomLayout(View view, int left, int top, int right, int bottom) {
        return false;
    }

    protected boolean canDismissWithTouchOutside() {
        return true;
    }

    public TextView getTitleView() {
        return this.titleView;
    }

    protected void onContainerTranslationYChanged(float translationY) {
    }

    private void cancelSheetAnimation() {
        AnimatorSet animatorSet = this.currentSheetAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.currentSheetAnimation = null;
            this.currentSheetAnimationType = 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startOpenAnimation() {
        if (this.dismissed) {
            return;
        }
        this.containerView.setVisibility(0);
        if (!onCustomOpenAnimation()) {
            if (Build.VERSION.SDK_INT >= 20 && this.useHardwareLayer) {
                this.container.setLayerType(2, null);
            }
            this.containerView.setTranslationY(r0.getMeasuredHeight());
            this.currentSheetAnimationType = 1;
            AnimatorSet animatorSet = new AnimatorSet();
            this.currentSheetAnimation = animatorSet;
            Animator[] animatorArr = new Animator[2];
            animatorArr[0] = ObjectAnimator.ofFloat(this.containerView, (Property<ViewGroup, Float>) View.TRANSLATION_Y, 0.0f);
            ColorDrawable colorDrawable = this.backDrawable;
            Property<ColorDrawable, Integer> property = AnimationProperties.COLOR_DRAWABLE_ALPHA;
            int[] iArr = new int[1];
            iArr[0] = this.dimBehind ? 51 : 0;
            animatorArr[1] = ObjectAnimator.ofInt(colorDrawable, property, iArr);
            animatorSet.playTogether(animatorArr);
            this.currentSheetAnimation.setDuration(400L);
            this.currentSheetAnimation.setStartDelay(20L);
            this.currentSheetAnimation.setInterpolator(this.openInterpolator);
            this.currentSheetAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.BottomSheet.4
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (BottomSheet.this.currentSheetAnimation != null && BottomSheet.this.currentSheetAnimation.equals(animation)) {
                        BottomSheet.this.currentSheetAnimation = null;
                        BottomSheet.this.currentSheetAnimationType = 0;
                        BottomSheet.this.isAnimationed = true;
                        if (BottomSheet.this.delegate != null) {
                            BottomSheet.this.delegate.onOpenAnimationEnd();
                        }
                        if (BottomSheet.this.useHardwareLayer) {
                            BottomSheet.this.container.setLayerType(0, null);
                        }
                        if (BottomSheet.this.isFullscreen) {
                            WindowManager.LayoutParams params = BottomSheet.this.getWindow().getAttributes();
                            params.flags &= -1025;
                            BottomSheet.this.getWindow().setAttributes(params);
                        }
                    }
                    NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 512);
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (BottomSheet.this.currentSheetAnimation != null && BottomSheet.this.currentSheetAnimation.equals(animation)) {
                        BottomSheet.this.currentSheetAnimation = null;
                        BottomSheet.this.currentSheetAnimationType = 0;
                    }
                }
            });
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 512);
            this.currentSheetAnimation.start();
        }
    }

    public void setDelegate(BottomSheetDelegateInterface bottomSheetDelegate) {
        this.delegate = bottomSheetDelegate;
    }

    public FrameLayout getContainer() {
        return this.container;
    }

    public ViewGroup getSheetContainer() {
        return this.containerView;
    }

    public int getTag() {
        return this.tag;
    }

    public void setDimBehind(boolean value) {
        this.dimBehind = value;
    }

    public void setItemText(int item, CharSequence text) {
        if (item < 0 || item >= this.itemViews.size()) {
            return;
        }
        BottomSheetCell cell = this.itemViews.get(item);
        cell.textView.setText(text);
    }

    public void setItemColor(int item, int color, int icon) {
        if (item < 0 || item >= this.itemViews.size()) {
            return;
        }
        BottomSheetCell cell = this.itemViews.get(item);
        cell.textView.setTextColor(color);
        cell.imageView.setColorFilter(new PorterDuffColorFilter(icon, PorterDuff.Mode.MULTIPLY));
    }

    public void setItems(CharSequence[] i, int[] icons, DialogInterface.OnClickListener listener) {
        this.items = i;
        this.itemIcons = icons;
        this.onClickListener = listener;
    }

    public void setTitleColor(int color) {
        TextView textView = this.titleView;
        if (textView == null) {
            return;
        }
        textView.setTextColor(color);
    }

    public boolean isDismissed() {
        return this.dismissed;
    }

    public void dismissWithButtonClick(int item) {
        if (this.dismissed) {
            return;
        }
        this.dismissed = true;
        cancelSheetAnimation();
        this.currentSheetAnimationType = 2;
        AnimatorSet animatorSet = new AnimatorSet();
        this.currentSheetAnimation = animatorSet;
        animatorSet.playTogether(ObjectAnimator.ofFloat(this.containerView, "translationY", r3.getMeasuredHeight() + AndroidUtilities.dp(10.0f)), ObjectAnimator.ofInt(this.backDrawable, "alpha", 0));
        this.currentSheetAnimation.setDuration(180L);
        this.currentSheetAnimation.setInterpolator(CubicBezierInterpolator.EASE_OUT);
        this.currentSheetAnimation.addListener(new AnonymousClass5(item));
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 512);
        this.currentSheetAnimation.start();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.actionbar.BottomSheet$5, reason: invalid class name */
    class AnonymousClass5 extends AnimatorListenerAdapter {
        final /* synthetic */ int val$item;

        AnonymousClass5(int i) {
            this.val$item = i;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            if (BottomSheet.this.currentSheetAnimation != null && BottomSheet.this.currentSheetAnimation.equals(animation)) {
                BottomSheet.this.currentSheetAnimation = null;
                BottomSheet.this.currentSheetAnimationType = 0;
                if (BottomSheet.this.onClickListener != null) {
                    BottomSheet.this.onClickListener.onClick(BottomSheet.this, this.val$item);
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$BottomSheet$5$mm1GMebVo5-XCcS_T4JaLZpq09U
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onAnimationEnd$0$BottomSheet$5();
                    }
                });
            }
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 512);
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$BottomSheet$5() {
            try {
                BottomSheet.super.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animation) {
            if (BottomSheet.this.currentSheetAnimation != null && BottomSheet.this.currentSheetAnimation.equals(animation)) {
                BottomSheet.this.currentSheetAnimation = null;
                BottomSheet.this.currentSheetAnimationType = 0;
            }
        }
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        BottomSheetDelegateInterface bottomSheetDelegateInterface = this.delegate;
        if ((bottomSheetDelegateInterface != null && !bottomSheetDelegateInterface.canDismiss()) || this.dismissed) {
            return;
        }
        this.dismissed = true;
        cancelSheetAnimation();
        if (!this.allowCustomAnimation || !onCustomCloseAnimation()) {
            this.currentSheetAnimationType = 2;
            AnimatorSet animatorSet = new AnimatorSet();
            this.currentSheetAnimation = animatorSet;
            animatorSet.playTogether(ObjectAnimator.ofFloat(this.containerView, "translationY", r3.getMeasuredHeight() + AndroidUtilities.dp(10.0f)), ObjectAnimator.ofInt(this.backDrawable, "alpha", 0));
            if (this.useFastDismiss) {
                int height = this.containerView.getMeasuredHeight();
                this.currentSheetAnimation.setDuration(Math.max(60, (int) (((height - this.containerView.getTranslationY()) * 180.0f) / height)));
                this.useFastDismiss = false;
            } else {
                this.currentSheetAnimation.setDuration(180L);
            }
            this.currentSheetAnimation.setInterpolator(CubicBezierInterpolator.EASE_OUT);
            this.currentSheetAnimation.addListener(new AnonymousClass6());
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 512);
            this.currentSheetAnimation.start();
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.actionbar.BottomSheet$6, reason: invalid class name */
    class AnonymousClass6 extends AnimatorListenerAdapter {
        AnonymousClass6() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            if (BottomSheet.this.currentSheetAnimation != null && BottomSheet.this.currentSheetAnimation.equals(animation)) {
                BottomSheet.this.currentSheetAnimation = null;
                BottomSheet.this.currentSheetAnimationType = 0;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$BottomSheet$6$27WWqRJ9LEJT4gtf2EwTv2Gs8yM
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onAnimationEnd$0$BottomSheet$6();
                    }
                });
            }
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 512);
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$BottomSheet$6() {
            try {
                BottomSheet.this.dismissInternal();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animation) {
            if (BottomSheet.this.currentSheetAnimation != null && BottomSheet.this.currentSheetAnimation.equals(animation)) {
                BottomSheet.this.currentSheetAnimation = null;
                BottomSheet.this.currentSheetAnimationType = 0;
            }
        }
    }

    public void dismissInternal() {
        try {
            super.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    protected boolean onCustomCloseAnimation() {
        return false;
    }

    protected boolean onCustomOpenAnimation() {
        return false;
    }

    public static class Builder {
        private BottomSheet bottomSheet;

        public Builder(Context context, boolean needFocus, int backgroundType) {
            this.bottomSheet = new BottomSheet(context, needFocus, backgroundType);
        }

        public Builder(Context context) {
            this.bottomSheet = new BottomSheet(context, false, 1);
        }

        public Builder(Context context, boolean needFocus) {
            this.bottomSheet = new BottomSheet(context, false, 1);
        }

        public Builder(Context context, int type) {
            this.bottomSheet = new BottomSheet(context, false, type);
        }

        public Builder setItems(CharSequence[] items, DialogInterface.OnClickListener onClickListener) {
            this.bottomSheet.items = items;
            this.bottomSheet.onClickListener = onClickListener;
            return this;
        }

        public Builder setItems(CharSequence[] items, int[] icons, DialogInterface.OnClickListener onClickListener) {
            this.bottomSheet.items = items;
            this.bottomSheet.itemIcons = icons;
            this.bottomSheet.onClickListener = onClickListener;
            return this;
        }

        public Builder setCustomView(View view) {
            this.bottomSheet.customView = view;
            return this;
        }

        public Builder setTitle(CharSequence title) {
            this.bottomSheet.title = title;
            return this;
        }

        public BottomSheet create() {
            return this.bottomSheet;
        }

        public BottomSheet setDimBehind(boolean value) {
            this.bottomSheet.dimBehind = value;
            return this.bottomSheet;
        }

        public BottomSheet show() {
            this.bottomSheet.show();
            return this.bottomSheet;
        }

        public Builder setTag(int tag) {
            this.bottomSheet.tag = tag;
            return this;
        }

        public Builder setUseHardwareLayer(boolean value) {
            this.bottomSheet.useHardwareLayer = value;
            return this;
        }

        public Builder setDelegate(BottomSheetDelegate delegate) {
            this.bottomSheet.setDelegate(delegate);
            return this;
        }

        public Builder setApplyTopPadding(boolean value) {
            this.bottomSheet.applyTopPadding = value;
            return this;
        }

        public Builder setApplyBottomPadding(boolean value) {
            this.bottomSheet.applyBottomPadding = value;
            return this;
        }

        public Runnable getDismissRunnable() {
            return this.bottomSheet.dismissRunnable;
        }

        public BottomSheet setUseFullWidth(boolean value) {
            this.bottomSheet.fullWidth = value;
            return this.bottomSheet;
        }

        public BottomSheet setUseFullscreen(boolean value) {
            this.bottomSheet.isFullscreen = value;
            return this.bottomSheet;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getLeftInset() {
        if (this.lastInsets != null && Build.VERSION.SDK_INT >= 21) {
            return this.lastInsets.getSystemWindowInsetLeft();
        }
        return 0;
    }

    protected int getRightInset() {
        if (this.lastInsets != null && Build.VERSION.SDK_INT >= 21) {
            return this.lastInsets.getSystemWindowInsetRight();
        }
        return 0;
    }

    public void onConfigurationChanged(Configuration newConfig) {
    }

    public void onContainerDraw(Canvas canvas) {
    }
}
