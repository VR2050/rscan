package im.uwrkaxlmjj.ui.actionbar;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.fragment.app.FragmentActivity;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.ui.IndexActivity;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.components.CubicBezierInterpolator;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ActionBarLayout extends FrameLayout {
    private static Drawable headerShadowDrawable;
    private static Drawable layerShadowDrawable;
    private static Paint scrimPaint;
    private AccelerateDecelerateInterpolator accelerateDecelerateInterpolator;
    private int[][] animateEndColors;
    private Theme.ThemeInfo animateSetThemeAfterAnimation;
    private boolean animateSetThemeNightAfterAnimation;
    private int[][] animateStartColors;
    private boolean animateThemeAfterAnimation;
    protected boolean animationInProgress;
    private float animationProgress;
    private Runnable animationRunnable;
    private View backgroundView;
    private boolean beginTrackingSent;
    private LinearLayoutContainer containerView;
    private LinearLayoutContainer containerViewBack;
    private ActionBar currentActionBar;
    private AnimatorSet currentAnimation;
    private DecelerateInterpolator decelerateInterpolator;
    private Runnable delayedOpenAnimationRunnable;
    private ActionBarLayoutDelegate delegate;
    private DrawerLayoutContainer drawerLayoutContainer;
    private ArrayList<BaseFragment> fragmentsBackGround;
    public ArrayList<BaseFragment> fragmentsStack;
    private boolean inActionMode;
    private boolean inPreviewMode;
    public float innerTranslationX;
    private long lastFrameTime;
    private boolean maybeStartTracking;
    private Runnable onCloseAnimationEndRunnable;
    private Runnable onOpenAnimationEndRunnable;
    private Runnable overlayAction;
    protected FragmentActivity parentActivity;
    private ThemeDescription[] presentingFragmentDescriptions;
    private ColorDrawable previewBackgroundDrawable;
    private boolean rebuildAfterAnimation;
    private boolean rebuildLastAfterAnimation;
    private boolean removeActionBarExtraHeight;
    private boolean showLastAfterAnimation;
    protected boolean startedTracking;
    private int startedTrackingPointerId;
    private int startedTrackingX;
    private int startedTrackingY;
    private float themeAnimationValue;
    private ThemeDescription.ThemeDescriptionDelegate[] themeAnimatorDelegate;
    private ThemeDescription[][] themeAnimatorDescriptions;
    private AnimatorSet themeAnimatorSet;
    private String titleOverlayText;
    private int titleOverlayTextId;
    private boolean transitionAnimationInProgress;
    private boolean transitionAnimationPreviewMode;
    private long transitionAnimationStartTime;
    private boolean useAlphaAnimations;
    private VelocityTracker velocityTracker;
    private Runnable waitingForKeyboardCloseRunnable;

    public interface ActionBarLayoutDelegate {
        boolean needAddFragmentToStack(BaseFragment baseFragment, ActionBarLayout actionBarLayout);

        boolean needCloseLastFragment(ActionBarLayout actionBarLayout);

        boolean needPresentFragment(BaseFragment baseFragment, boolean z, boolean z2, ActionBarLayout actionBarLayout);

        boolean onPreIme();

        void onRebuildAllFragments(ActionBarLayout actionBarLayout, boolean z);
    }

    public class LinearLayoutContainer extends LinearLayout {
        private boolean isKeyboardVisible;
        private Rect rect;

        public LinearLayoutContainer(Context context) {
            super(context);
            this.rect = new Rect();
            setOrientation(1);
        }

        @Override // android.view.ViewGroup
        protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
            if (child instanceof ActionBar) {
                return super.drawChild(canvas, child, drawingTime);
            }
            int actionBarHeight = 0;
            int childCount = getChildCount();
            int a = 0;
            while (true) {
                if (a >= childCount) {
                    break;
                }
                View view = getChildAt(a);
                if (view == child || !(view instanceof ActionBar) || view.getVisibility() != 0) {
                    a++;
                } else if (((ActionBar) view).getCastShadows()) {
                    actionBarHeight = view.getMeasuredHeight();
                }
            }
            boolean result = super.drawChild(canvas, child, drawingTime);
            if (actionBarHeight != 0 && ActionBarLayout.headerShadowDrawable != null) {
                ActionBarLayout.headerShadowDrawable.setBounds(0, actionBarHeight, getMeasuredWidth(), ActionBarLayout.headerShadowDrawable.getIntrinsicHeight() + actionBarHeight);
                ActionBarLayout.headerShadowDrawable.draw(canvas);
            }
            return result;
        }

        @Override // android.view.View
        public boolean hasOverlappingRendering() {
            if (Build.VERSION.SDK_INT >= 28) {
                return true;
            }
            return false;
        }

        @Override // android.widget.LinearLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            super.onLayout(changed, l, t, r, b);
            View rootView = getRootView();
            getWindowVisibleDisplayFrame(this.rect);
            int usableViewHeight = (rootView.getHeight() - (this.rect.top != 0 ? AndroidUtilities.statusBarHeight : 0)) - AndroidUtilities.getViewInset(rootView);
            this.isKeyboardVisible = usableViewHeight - (this.rect.bottom - this.rect.top) > 0;
            if (ActionBarLayout.this.waitingForKeyboardCloseRunnable != null && !ActionBarLayout.this.containerView.isKeyboardVisible && !ActionBarLayout.this.containerViewBack.isKeyboardVisible) {
                AndroidUtilities.cancelRunOnUIThread(ActionBarLayout.this.waitingForKeyboardCloseRunnable);
                ActionBarLayout.this.waitingForKeyboardCloseRunnable.run();
                ActionBarLayout.this.waitingForKeyboardCloseRunnable = null;
            }
        }

        @Override // android.view.ViewGroup, android.view.View
        public boolean dispatchTouchEvent(MotionEvent ev) {
            if ((ActionBarLayout.this.inPreviewMode || ActionBarLayout.this.transitionAnimationPreviewMode) && (ev.getActionMasked() == 0 || ev.getActionMasked() == 5)) {
                return false;
            }
            try {
                if (ActionBarLayout.this.inPreviewMode && this == ActionBarLayout.this.containerView) {
                    return false;
                }
                return super.dispatchTouchEvent(ev);
            } catch (Throwable e) {
                FileLog.e(e);
                return false;
            }
        }
    }

    public ActionBarLayout(Context context) {
        super(context);
        this.decelerateInterpolator = new DecelerateInterpolator(1.5f);
        this.accelerateDecelerateInterpolator = new AccelerateDecelerateInterpolator();
        this.animateStartColors = new int[2][];
        this.animateEndColors = new int[2][];
        this.themeAnimatorDescriptions = new ThemeDescription[2][];
        this.themeAnimatorDelegate = new ThemeDescription.ThemeDescriptionDelegate[2];
        this.parentActivity = (FragmentActivity) context;
        if (layerShadowDrawable == null) {
            layerShadowDrawable = getResources().getDrawable(R.drawable.layer_shadow);
            headerShadowDrawable = getResources().getDrawable(R.drawable.header_shadow).mutate();
            scrimPaint = new Paint();
        }
    }

    public void init(ArrayList<BaseFragment> stack) {
        this.fragmentsStack = stack;
        this.fragmentsBackGround = new ArrayList<>();
        LinearLayoutContainer linearLayoutContainer = new LinearLayoutContainer(this.parentActivity);
        this.containerViewBack = linearLayoutContainer;
        addView(linearLayoutContainer);
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.containerViewBack.getLayoutParams();
        layoutParams.width = -1;
        layoutParams.height = -1;
        layoutParams.gravity = 51;
        this.containerViewBack.setLayoutParams(layoutParams);
        LinearLayoutContainer linearLayoutContainer2 = new LinearLayoutContainer(this.parentActivity);
        this.containerView = linearLayoutContainer2;
        addView(linearLayoutContainer2);
        FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.containerView.getLayoutParams();
        layoutParams2.width = -1;
        layoutParams2.height = -1;
        layoutParams2.gravity = 51;
        this.containerView.setLayoutParams(layoutParams2);
        for (BaseFragment fragment : this.fragmentsStack) {
            fragment.setParentLayout(this);
        }
    }

    @Override // android.view.View
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        if (!this.fragmentsStack.isEmpty()) {
            BaseFragment lastFragment = this.fragmentsStack.get(r0.size() - 1);
            lastFragment.onConfigurationChanged(newConfig);
            if (lastFragment.visibleDialog instanceof BottomSheet) {
                ((BottomSheet) lastFragment.visibleDialog).onConfigurationChanged(newConfig);
            }
        }
    }

    public void drawHeaderShadow(Canvas canvas, int y) {
        Drawable drawable = headerShadowDrawable;
        if (drawable != null) {
            drawable.setBounds(0, y, getMeasuredWidth(), headerShadowDrawable.getIntrinsicHeight() + y);
            headerShadowDrawable.draw(canvas);
        }
    }

    public void setInnerTranslationX(float value) {
        this.innerTranslationX = value;
        invalidate();
    }

    public float getInnerTranslationX() {
        return this.innerTranslationX;
    }

    public void dismissDialogs() {
        if (!this.fragmentsStack.isEmpty()) {
            BaseFragment lastFragment = this.fragmentsStack.get(r0.size() - 1);
            lastFragment.dismissCurrentDialog();
        }
    }

    public void onResume() {
        if (this.transitionAnimationInProgress) {
            AnimatorSet animatorSet = this.currentAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.currentAnimation = null;
            }
            if (this.onCloseAnimationEndRunnable != null) {
                onCloseAnimationEnd();
            } else if (this.onOpenAnimationEndRunnable != null) {
                onOpenAnimationEnd();
            }
        }
        if (!this.fragmentsStack.isEmpty()) {
            BaseFragment lastFragment = this.fragmentsStack.get(r0.size() - 1);
            lastFragment.onResume();
        }
    }

    public void onPause() {
        if (!this.fragmentsStack.isEmpty()) {
            BaseFragment lastFragment = this.fragmentsStack.get(r0.size() - 1);
            lastFragment.onPause();
        }
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        return this.animationInProgress || checkTransitionAnimation() || onTouchEvent(ev);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
        onTouchEvent(null);
        super.requestDisallowInterceptTouchEvent(disallowIntercept);
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchKeyEventPreIme(KeyEvent event) {
        if (event != null && event.getKeyCode() == 4 && event.getAction() == 1) {
            ActionBarLayoutDelegate actionBarLayoutDelegate = this.delegate;
            return (actionBarLayoutDelegate != null && actionBarLayoutDelegate.onPreIme()) || super.dispatchKeyEventPreIme(event);
        }
        return super.dispatchKeyEventPreIme(event);
    }

    @Override // android.view.ViewGroup
    protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
        int clipLeft;
        int clipRight;
        LinearLayoutContainer linearLayoutContainer;
        View view;
        float opacity;
        int width = (getWidth() - getPaddingLeft()) - getPaddingRight();
        int translationX = ((int) this.innerTranslationX) + getPaddingRight();
        int clipLeft2 = getPaddingLeft();
        int clipRight2 = getPaddingLeft() + width;
        if (child == this.containerViewBack) {
            clipLeft = clipLeft2;
            clipRight = translationX;
        } else if (child != this.containerView) {
            clipLeft = clipLeft2;
            clipRight = clipRight2;
        } else {
            clipLeft = translationX;
            clipRight = clipRight2;
        }
        int restoreCount = canvas.save();
        if (!this.transitionAnimationInProgress && !this.inPreviewMode) {
            canvas.clipRect(clipLeft, 0, clipRight, getHeight());
        }
        if ((this.inPreviewMode || this.transitionAnimationPreviewMode) && child == (linearLayoutContainer = this.containerView) && (view = linearLayoutContainer.getChildAt(0)) != null) {
            this.previewBackgroundDrawable.setBounds(0, 0, getMeasuredWidth(), getMeasuredHeight());
            this.previewBackgroundDrawable.draw(canvas);
            int x = (getMeasuredWidth() - AndroidUtilities.dp(24.0f)) / 2;
            int y = (int) ((view.getTop() + this.containerView.getTranslationY()) - AndroidUtilities.dp((Build.VERSION.SDK_INT < 21 ? 20 : 0) + 12));
            Theme.moveUpDrawable.setBounds(x, y, AndroidUtilities.dp(24.0f) + x, AndroidUtilities.dp(24.0f) + y);
            Theme.moveUpDrawable.draw(canvas);
        }
        boolean result = super.drawChild(canvas, child, drawingTime);
        canvas.restoreToCount(restoreCount);
        if (translationX != 0) {
            if (child == this.containerView) {
                float alpha = Math.max(0.0f, Math.min((width - translationX) / AndroidUtilities.dp(20.0f), 1.0f));
                Drawable drawable = layerShadowDrawable;
                drawable.setBounds(translationX - drawable.getIntrinsicWidth(), child.getTop(), translationX, child.getBottom());
                layerShadowDrawable.setAlpha((int) (255.0f * alpha));
                layerShadowDrawable.draw(canvas);
            } else if (child == this.containerViewBack) {
                float opacity2 = Math.min(0.8f, (width - translationX) / width);
                if (opacity2 >= 0.0f) {
                    opacity = opacity2;
                } else {
                    opacity = 0.0f;
                }
                scrimPaint.setColor(((int) (153.0f * opacity)) << 24);
                canvas.drawRect(clipLeft, 0.0f, clipRight, getHeight(), scrimPaint);
            }
        }
        return result;
    }

    public void setDelegate(ActionBarLayoutDelegate delegate) {
        this.delegate = delegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onSlideAnimationEnd(boolean backAnimation) {
        ViewGroup parent;
        ViewGroup parent2;
        if (!backAnimation) {
            if (this.fragmentsStack.size() < 2) {
                return;
            }
            BaseFragment lastFragment = this.fragmentsStack.get(r0.size() - 1);
            lastFragment.onPause();
            lastFragment.onFragmentDestroy();
            lastFragment.setParentLayout(null);
            this.fragmentsStack.remove(r1.size() - 1);
            LinearLayoutContainer temp = this.containerView;
            LinearLayoutContainer linearLayoutContainer = this.containerViewBack;
            this.containerView = linearLayoutContainer;
            this.containerViewBack = temp;
            bringChildToFront(linearLayoutContainer);
            BaseFragment lastFragment2 = this.fragmentsStack.get(r2.size() - 1);
            this.currentActionBar = lastFragment2.actionBar;
            lastFragment2.onResume();
            lastFragment2.onBecomeFullyVisible();
        } else if (this.fragmentsStack.size() >= 2) {
            ArrayList<BaseFragment> arrayList = this.fragmentsStack;
            BaseFragment lastFragment3 = arrayList.get(arrayList.size() - 2);
            lastFragment3.onPause();
            if (lastFragment3.fragmentView != null && (parent2 = (ViewGroup) lastFragment3.fragmentView.getParent()) != null) {
                lastFragment3.onRemoveFromParent();
                parent2.removeView(lastFragment3.fragmentView);
            }
            if (lastFragment3.actionBar != null && lastFragment3.actionBar.getAddToContainer() && (parent = (ViewGroup) lastFragment3.actionBar.getParent()) != null) {
                parent.removeView(lastFragment3.actionBar);
            }
        }
        this.containerViewBack.setVisibility(8);
        this.startedTracking = false;
        this.animationInProgress = false;
        this.containerView.setTranslationX(0.0f);
        this.containerViewBack.setTranslationX(0.0f);
        setInnerTranslationX(0.0f);
    }

    private void prepareForMoving(MotionEvent ev) {
        this.maybeStartTracking = false;
        this.startedTracking = true;
        this.startedTrackingX = (int) ev.getX();
        this.containerViewBack.setVisibility(0);
        this.beginTrackingSent = false;
        BaseFragment lastFragment = this.fragmentsStack.get(r1.size() - 2);
        View fragmentView = lastFragment.fragmentView;
        if (fragmentView == null) {
            fragmentView = lastFragment.createView(this.parentActivity);
        }
        ViewGroup parent = (ViewGroup) fragmentView.getParent();
        if (parent != null) {
            lastFragment.onRemoveFromParent();
            parent.removeView(fragmentView);
        }
        if (lastFragment.actionBar != null && lastFragment.actionBar.getAddToContainer()) {
            ViewGroup parent2 = (ViewGroup) lastFragment.actionBar.getParent();
            if (parent2 != null) {
                parent2.removeView(lastFragment.actionBar);
            }
            if (this.removeActionBarExtraHeight) {
                lastFragment.actionBar.setOccupyStatusBar(false);
            }
            this.containerViewBack.addView(lastFragment.actionBar);
            lastFragment.actionBar.setTitleOverlayText(this.titleOverlayText, this.titleOverlayTextId, this.overlayAction);
        }
        this.containerViewBack.addView(fragmentView);
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) fragmentView.getLayoutParams();
        layoutParams.width = -1;
        layoutParams.height = -1;
        layoutParams.leftMargin = 0;
        layoutParams.rightMargin = 0;
        layoutParams.bottomMargin = 0;
        layoutParams.topMargin = 0;
        fragmentView.setLayoutParams(layoutParams);
        if (!lastFragment.hasOwnBackground && fragmentView.getBackground() == null) {
            fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        }
        lastFragment.onResume();
        if (this.themeAnimatorSet != null) {
            this.presentingFragmentDescriptions = lastFragment.getThemeDescriptions();
        }
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent ev) {
        float distToMove;
        if (checkTransitionAnimation() || this.inActionMode || this.animationInProgress) {
            return false;
        }
        if (this.fragmentsStack.size() > 1) {
            if (ev == null || ev.getAction() != 0 || this.startedTracking || this.maybeStartTracking) {
                if (ev == null || ev.getAction() != 2 || ev.getPointerId(0) != this.startedTrackingPointerId) {
                    if (ev != null && ev.getPointerId(0) == this.startedTrackingPointerId && (ev.getAction() == 3 || ev.getAction() == 1 || ev.getAction() == 6)) {
                        if (this.velocityTracker == null) {
                            this.velocityTracker = VelocityTracker.obtain();
                        }
                        this.velocityTracker.computeCurrentVelocity(1000);
                        ArrayList<BaseFragment> arrayList = this.fragmentsStack;
                        BaseFragment currentFragment = arrayList.get(arrayList.size() - 1);
                        if (!this.inPreviewMode && !this.transitionAnimationPreviewMode && !this.startedTracking && currentFragment.swipeBackEnabled) {
                            float velX = this.velocityTracker.getXVelocity();
                            float velY = this.velocityTracker.getYVelocity();
                            if (velX >= 3500.0f && velX > Math.abs(velY) && currentFragment.canBeginSlide()) {
                                prepareForMoving(ev);
                                if (!this.beginTrackingSent) {
                                    if (((Activity) getContext()).getCurrentFocus() != null) {
                                        AndroidUtilities.hideKeyboard(((Activity) getContext()).getCurrentFocus());
                                    }
                                    this.beginTrackingSent = true;
                                }
                            }
                        }
                        if (this.startedTracking) {
                            float x = this.containerView.getX();
                            AnimatorSet animatorSet = new AnimatorSet();
                            float velX2 = this.velocityTracker.getXVelocity();
                            float velY2 = this.velocityTracker.getYVelocity();
                            final boolean backAnimation = x < ((float) this.containerView.getMeasuredWidth()) / 3.0f && (velX2 < 3500.0f || velX2 < velY2);
                            if (!backAnimation) {
                                distToMove = this.containerView.getMeasuredWidth() - x;
                                animatorSet.playTogether(ObjectAnimator.ofFloat(this.containerView, "translationX", r15.getMeasuredWidth()), ObjectAnimator.ofFloat(this, "innerTranslationX", this.containerView.getMeasuredWidth()));
                            } else {
                                distToMove = x;
                                animatorSet.playTogether(ObjectAnimator.ofFloat(this.containerView, "translationX", 0.0f), ObjectAnimator.ofFloat(this, "innerTranslationX", 0.0f));
                            }
                            animatorSet.setDuration(Math.max((int) ((200.0f / this.containerView.getMeasuredWidth()) * distToMove), 50));
                            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.1
                                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                public void onAnimationEnd(Animator animator) {
                                    ActionBarLayout.this.onSlideAnimationEnd(backAnimation);
                                }
                            });
                            animatorSet.start();
                            this.animationInProgress = true;
                        } else {
                            this.maybeStartTracking = false;
                            this.startedTracking = false;
                        }
                        VelocityTracker velocityTracker = this.velocityTracker;
                        if (velocityTracker != null) {
                            velocityTracker.recycle();
                            this.velocityTracker = null;
                        }
                    } else if (ev == null) {
                        this.maybeStartTracking = false;
                        this.startedTracking = false;
                        VelocityTracker velocityTracker2 = this.velocityTracker;
                        if (velocityTracker2 != null) {
                            velocityTracker2.recycle();
                            this.velocityTracker = null;
                        }
                    }
                } else {
                    if (this.velocityTracker == null) {
                        this.velocityTracker = VelocityTracker.obtain();
                    }
                    int dx = Math.max(0, (int) (ev.getX() - this.startedTrackingX));
                    int dy = Math.abs(((int) ev.getY()) - this.startedTrackingY);
                    this.velocityTracker.addMovement(ev);
                    if (!this.inPreviewMode && this.maybeStartTracking && !this.startedTracking && dx >= AndroidUtilities.getPixelsInCM(0.4f, true) && Math.abs(dx) / 3 > dy) {
                        ArrayList<BaseFragment> arrayList2 = this.fragmentsStack;
                        if (arrayList2.get(arrayList2.size() - 1).canBeginSlide()) {
                            prepareForMoving(ev);
                        } else {
                            this.maybeStartTracking = false;
                        }
                    } else if (this.startedTracking) {
                        if (!this.beginTrackingSent) {
                            if (this.parentActivity.getCurrentFocus() != null) {
                                AndroidUtilities.hideKeyboard(this.parentActivity.getCurrentFocus());
                            }
                            ArrayList<BaseFragment> arrayList3 = this.fragmentsStack;
                            arrayList3.get(arrayList3.size() - 1).onBeginSlide();
                            this.beginTrackingSent = true;
                        }
                        this.containerView.setTranslationX(dx);
                        setInnerTranslationX(dx);
                    }
                }
            } else {
                ArrayList<BaseFragment> arrayList4 = this.fragmentsStack;
                if (!arrayList4.get(arrayList4.size() - 1).swipeBackEnabled) {
                    return false;
                }
                this.startedTrackingPointerId = ev.getPointerId(0);
                this.maybeStartTracking = true;
                this.startedTrackingX = (int) ev.getX();
                this.startedTrackingY = (int) ev.getY();
                VelocityTracker velocityTracker3 = this.velocityTracker;
                if (velocityTracker3 != null) {
                    velocityTracker3.clear();
                }
            }
        }
        return this.startedTracking;
    }

    public void onBackPressed() {
        ActionBar actionBar;
        if (this.transitionAnimationPreviewMode || this.startedTracking || checkTransitionAnimation() || this.fragmentsStack.isEmpty()) {
            return;
        }
        if (!this.currentActionBar.isActionModeShowed() && (actionBar = this.currentActionBar) != null && actionBar.isSearchFieldVisible) {
            this.currentActionBar.closeSearchField();
            return;
        }
        ArrayList<BaseFragment> arrayList = this.fragmentsStack;
        BaseFragment lastFragment = arrayList.get(arrayList.size() - 1);
        if (lastFragment.onBackPressed() && !this.fragmentsStack.isEmpty()) {
            closeLastFragment(true);
        }
    }

    public void onLowMemory() {
        for (BaseFragment fragment : this.fragmentsStack) {
            fragment.onLowMemory();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onAnimationEndCheck(boolean byCheck) {
        onCloseAnimationEnd();
        onOpenAnimationEnd();
        Runnable runnable = this.waitingForKeyboardCloseRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.waitingForKeyboardCloseRunnable = null;
        }
        AnimatorSet animatorSet = this.currentAnimation;
        if (animatorSet != null) {
            if (byCheck) {
                animatorSet.cancel();
            }
            this.currentAnimation = null;
        }
        Runnable runnable2 = this.animationRunnable;
        if (runnable2 != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable2);
            this.animationRunnable = null;
        }
        setAlpha(1.0f);
        this.containerView.setAlpha(1.0f);
        this.containerView.setScaleX(1.0f);
        this.containerView.setScaleY(1.0f);
        this.containerViewBack.setAlpha(1.0f);
        this.containerViewBack.setScaleX(1.0f);
        this.containerViewBack.setScaleY(1.0f);
    }

    public BaseFragment getLastFragment() {
        if (this.fragmentsStack.isEmpty()) {
            return null;
        }
        return this.fragmentsStack.get(r0.size() - 1);
    }

    public boolean checkTransitionAnimation() {
        if (this.transitionAnimationPreviewMode) {
            return false;
        }
        if (this.transitionAnimationInProgress && this.transitionAnimationStartTime < System.currentTimeMillis() - 1500) {
            onAnimationEndCheck(true);
        }
        return this.transitionAnimationInProgress;
    }

    private void presentFragmentInternalRemoveOld(boolean removeLast, BaseFragment fragment) {
        ViewGroup parent;
        ViewGroup parent2;
        if (fragment == null) {
            return;
        }
        fragment.onBecomeFullyHidden();
        fragment.onPause();
        if (removeLast) {
            fragment.onFragmentDestroy();
            fragment.setParentLayout(null);
            this.fragmentsStack.remove(fragment);
        } else {
            if (fragment.fragmentView != null && (parent2 = (ViewGroup) fragment.fragmentView.getParent()) != null) {
                fragment.onRemoveFromParent();
                parent2.removeView(fragment.fragmentView);
            }
            if (fragment.actionBar != null && fragment.actionBar.getAddToContainer() && (parent = (ViewGroup) fragment.actionBar.getParent()) != null) {
                parent.removeView(fragment.actionBar);
            }
        }
        this.containerViewBack.setVisibility(8);
    }

    public boolean presentFragmentAsPreview(BaseFragment fragment) {
        return presentFragment(fragment, false, false, true, true);
    }

    public boolean presentFragment(BaseFragment fragment) {
        return presentFragment(fragment, false, false, true, false);
    }

    public boolean presentFragment(BaseFragment fragment, boolean removeLast) {
        return presentFragment(fragment, removeLast, false, true, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startLayoutAnimation(final boolean open, final boolean first, final boolean preview) {
        if (first) {
            this.animationProgress = 0.0f;
            this.lastFrameTime = System.nanoTime() / 1000000;
        }
        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.2
            @Override // java.lang.Runnable
            public void run() {
                if (ActionBarLayout.this.animationRunnable == this) {
                    ActionBarLayout.this.animationRunnable = null;
                    if (first) {
                        ActionBarLayout.this.transitionAnimationStartTime = System.currentTimeMillis();
                    }
                    long newTime = System.nanoTime() / 1000000;
                    long dt = newTime - ActionBarLayout.this.lastFrameTime;
                    if (dt > 18) {
                        dt = 18;
                    }
                    ActionBarLayout.this.lastFrameTime = newTime;
                    ActionBarLayout.this.animationProgress += dt / 150.0f;
                    if (ActionBarLayout.this.animationProgress > 1.0f) {
                        ActionBarLayout.this.animationProgress = 1.0f;
                    }
                    float interpolated = ActionBarLayout.this.decelerateInterpolator.getInterpolation(ActionBarLayout.this.animationProgress);
                    if (open) {
                        ActionBarLayout.this.containerView.setAlpha(interpolated);
                        if (preview) {
                            ActionBarLayout.this.containerView.setScaleX((interpolated * 0.1f) + 0.9f);
                            ActionBarLayout.this.containerView.setScaleY((0.1f * interpolated) + 0.9f);
                            ActionBarLayout.this.previewBackgroundDrawable.setAlpha((int) (128.0f * interpolated));
                            Theme.moveUpDrawable.setAlpha((int) (255.0f * interpolated));
                            ActionBarLayout.this.containerView.invalidate();
                            ActionBarLayout.this.invalidate();
                        } else {
                            ActionBarLayout.this.containerView.setTranslationX(AndroidUtilities.dp(48.0f) * (1.0f - interpolated));
                        }
                    } else {
                        ActionBarLayout.this.containerViewBack.setAlpha(1.0f - interpolated);
                        if (preview) {
                            ActionBarLayout.this.containerViewBack.setScaleX(((1.0f - interpolated) * 0.1f) + 0.9f);
                            ActionBarLayout.this.containerViewBack.setScaleY(((1.0f - interpolated) * 0.1f) + 0.9f);
                            ActionBarLayout.this.previewBackgroundDrawable.setAlpha((int) ((1.0f - interpolated) * 128.0f));
                            Theme.moveUpDrawable.setAlpha((int) ((1.0f - interpolated) * 255.0f));
                            ActionBarLayout.this.containerView.invalidate();
                            ActionBarLayout.this.invalidate();
                        } else {
                            ActionBarLayout.this.containerViewBack.setTranslationX(AndroidUtilities.dp(48.0f) * interpolated);
                        }
                    }
                    if (ActionBarLayout.this.animationProgress < 1.0f) {
                        ActionBarLayout.this.startLayoutAnimation(open, false, preview);
                    } else {
                        ActionBarLayout.this.onAnimationEndCheck(false);
                    }
                }
            }
        };
        this.animationRunnable = runnable;
        AndroidUtilities.runOnUIThread(runnable);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startLayoutAnimationFromBottom(final boolean open, final boolean first, final boolean preview) {
        if (first) {
            this.animationProgress = 0.0f;
            this.lastFrameTime = System.nanoTime() / 1000000;
        }
        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.3
            @Override // java.lang.Runnable
            public void run() {
                if (ActionBarLayout.this.animationRunnable == this) {
                    ActionBarLayout.this.animationRunnable = null;
                    if (first) {
                        ActionBarLayout.this.transitionAnimationStartTime = System.currentTimeMillis();
                    }
                    long newTime = System.nanoTime() / 1000000;
                    long dt = newTime - ActionBarLayout.this.lastFrameTime;
                    if (dt > 18) {
                        dt = 18;
                    }
                    ActionBarLayout.this.lastFrameTime = newTime;
                    ActionBarLayout.this.animationProgress += dt / 150.0f;
                    if (ActionBarLayout.this.animationProgress > 1.0f) {
                        ActionBarLayout.this.animationProgress = 1.0f;
                    }
                    float interpolated = ActionBarLayout.this.decelerateInterpolator.getInterpolation(ActionBarLayout.this.animationProgress);
                    if (open) {
                        ActionBarLayout.this.containerView.setAlpha(interpolated);
                        if (preview) {
                            ActionBarLayout.this.containerView.setScaleX((interpolated * 0.1f) + 0.9f);
                            ActionBarLayout.this.containerView.setScaleY((0.1f * interpolated) + 0.9f);
                            ActionBarLayout.this.previewBackgroundDrawable.setAlpha((int) (128.0f * interpolated));
                            Theme.moveUpDrawable.setAlpha((int) (255.0f * interpolated));
                            ActionBarLayout.this.containerView.invalidate();
                            ActionBarLayout.this.invalidate();
                        } else {
                            ActionBarLayout.this.containerView.setTranslationY(AndroidUtilities.dp(48.0f) * (1.0f - interpolated));
                        }
                    } else {
                        ActionBarLayout.this.containerViewBack.setAlpha(1.0f - interpolated);
                        if (preview) {
                            ActionBarLayout.this.containerViewBack.setScaleX(((1.0f - interpolated) * 0.1f) + 0.9f);
                            ActionBarLayout.this.containerViewBack.setScaleY(((1.0f - interpolated) * 0.1f) + 0.9f);
                            ActionBarLayout.this.previewBackgroundDrawable.setAlpha((int) ((1.0f - interpolated) * 128.0f));
                            Theme.moveUpDrawable.setAlpha((int) ((1.0f - interpolated) * 255.0f));
                            ActionBarLayout.this.containerView.invalidate();
                            ActionBarLayout.this.invalidate();
                        } else {
                            ActionBarLayout.this.containerViewBack.setTranslationY(AndroidUtilities.dp(48.0f) * interpolated);
                        }
                    }
                    if (ActionBarLayout.this.animationProgress < 1.0f) {
                        ActionBarLayout.this.startLayoutAnimationFromBottom(open, false, preview);
                    } else {
                        ActionBarLayout.this.onAnimationEndCheck(false);
                    }
                }
            }
        };
        this.animationRunnable = runnable;
        AndroidUtilities.runOnUIThread(runnable);
    }

    public void resumeDelayedFragmentAnimation() {
        Runnable runnable = this.delayedOpenAnimationRunnable;
        if (runnable == null) {
            return;
        }
        AndroidUtilities.cancelRunOnUIThread(runnable);
        this.delayedOpenAnimationRunnable.run();
        this.delayedOpenAnimationRunnable = null;
    }

    public boolean isInPreviewMode() {
        return this.inPreviewMode || this.transitionAnimationPreviewMode;
    }

    public boolean presentFragment(final BaseFragment fragment, final boolean removeLast, boolean forceWithoutAnimation, boolean check, final boolean preview) {
        BaseFragment baseFragment;
        View fragmentView;
        boolean z;
        boolean z2;
        if (!checkTransitionAnimation()) {
            ActionBarLayoutDelegate actionBarLayoutDelegate = this.delegate;
            if ((actionBarLayoutDelegate != null && check && !actionBarLayoutDelegate.needPresentFragment(fragment, removeLast, forceWithoutAnimation, this)) || !fragment.onFragmentCreate()) {
                return false;
            }
            fragment.setInPreviewMode(preview);
            if (this.parentActivity.getCurrentFocus() != null) {
                AndroidUtilities.hideKeyboard(this.parentActivity.getCurrentFocus());
            }
            boolean needAnimation = preview || (!forceWithoutAnimation && MessagesController.getGlobalMainSettings().getBoolean("view_animations", true));
            if (this.fragmentsStack.isEmpty()) {
                baseFragment = null;
            } else {
                ArrayList<BaseFragment> arrayList = this.fragmentsStack;
                baseFragment = arrayList.get(arrayList.size() - 1);
            }
            final BaseFragment currentFragment = baseFragment;
            fragment.setParentLayout(this);
            View fragmentView2 = fragment.fragmentView;
            if (fragmentView2 == null) {
                fragmentView = fragment.createView(this.parentActivity);
            } else {
                ViewGroup parent = (ViewGroup) fragmentView2.getParent();
                if (parent != null) {
                    fragment.onRemoveFromParent();
                    parent.removeView(fragmentView2);
                }
                fragmentView = fragmentView2;
            }
            if (fragment.actionBar != null && fragment.actionBar.getAddToContainer()) {
                if (this.removeActionBarExtraHeight) {
                    fragment.actionBar.setOccupyStatusBar(false);
                }
                ViewGroup parent2 = (ViewGroup) fragment.actionBar.getParent();
                if (parent2 != null) {
                    parent2.removeView(fragment.actionBar);
                }
                this.containerViewBack.addView(fragment.actionBar);
                fragment.actionBar.setTitleOverlayText(this.titleOverlayText, this.titleOverlayTextId, this.overlayAction);
            }
            this.containerViewBack.addView(fragmentView);
            LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) fragmentView.getLayoutParams();
            layoutParams.width = -1;
            layoutParams.height = -1;
            if (preview) {
                int iDp = AndroidUtilities.dp(8.0f);
                layoutParams.leftMargin = iDp;
                layoutParams.rightMargin = iDp;
                int iDp2 = AndroidUtilities.dp(46.0f);
                layoutParams.bottomMargin = iDp2;
                layoutParams.topMargin = iDp2;
                layoutParams.topMargin += AndroidUtilities.statusBarHeight;
            } else {
                layoutParams.leftMargin = 0;
                layoutParams.rightMargin = 0;
                layoutParams.bottomMargin = 0;
                layoutParams.topMargin = 0;
            }
            fragmentView.setLayoutParams(layoutParams);
            this.fragmentsStack.add(fragment);
            fragment.onResume();
            this.currentActionBar = fragment.actionBar;
            if (!fragment.hasOwnBackground && fragmentView.getBackground() == null) {
                fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            LinearLayoutContainer temp = this.containerView;
            LinearLayoutContainer linearLayoutContainer = this.containerViewBack;
            this.containerView = linearLayoutContainer;
            this.containerViewBack = temp;
            linearLayoutContainer.setVisibility(0);
            setInnerTranslationX(0.0f);
            this.containerView.setTranslationY(0.0f);
            if (preview) {
                if (Build.VERSION.SDK_INT >= 21) {
                    fragmentView.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.4
                        @Override // android.view.ViewOutlineProvider
                        public void getOutline(View view, Outline outline) {
                            outline.setRoundRect(0, AndroidUtilities.statusBarHeight, view.getMeasuredWidth(), view.getMeasuredHeight(), AndroidUtilities.dp(6.0f));
                        }
                    });
                    fragmentView.setClipToOutline(true);
                    fragmentView.setElevation(AndroidUtilities.dp(4.0f));
                }
                if (this.previewBackgroundDrawable == null) {
                    this.previewBackgroundDrawable = new ColorDrawable(Integer.MIN_VALUE);
                }
                this.previewBackgroundDrawable.setAlpha(0);
                Theme.moveUpDrawable.setAlpha(0);
            }
            bringChildToFront(this.containerView);
            if (!needAnimation) {
                presentFragmentInternalRemoveOld(removeLast, currentFragment);
                View view = this.backgroundView;
                if (view != null) {
                    view.setVisibility(0);
                }
            }
            if (this.themeAnimatorSet != null) {
                this.presentingFragmentDescriptions = fragment.getThemeDescriptions();
            }
            if (needAnimation || preview) {
                if (this.useAlphaAnimations && this.fragmentsStack.size() == 1) {
                    presentFragmentInternalRemoveOld(removeLast, currentFragment);
                    this.transitionAnimationStartTime = System.currentTimeMillis();
                    this.transitionAnimationInProgress = true;
                    this.onOpenAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$TJ8_8WMxY2bHLhDQmtqqL-8Pptc
                        @Override // java.lang.Runnable
                        public final void run() {
                            ActionBarLayout.lambda$presentFragment$0(currentFragment, fragment);
                        }
                    };
                    ArrayList<Animator> animators = new ArrayList<>();
                    animators.add(ObjectAnimator.ofFloat(this, "alpha", 0.0f, 1.0f));
                    View view2 = this.backgroundView;
                    if (view2 != null) {
                        view2.setVisibility(0);
                        animators.add(ObjectAnimator.ofFloat(this.backgroundView, "alpha", 0.0f, 1.0f));
                    }
                    if (currentFragment == null) {
                        z2 = false;
                    } else {
                        z2 = false;
                        currentFragment.onTransitionAnimationStart(false, false);
                    }
                    fragment.onTransitionAnimationStart(true, z2);
                    AnimatorSet animatorSet = new AnimatorSet();
                    this.currentAnimation = animatorSet;
                    animatorSet.playTogether(animators);
                    this.currentAnimation.setInterpolator(this.accelerateDecelerateInterpolator);
                    this.currentAnimation.setDuration(200L);
                    this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.5
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            ActionBarLayout.this.onAnimationEndCheck(false);
                        }
                    });
                    this.currentAnimation.start();
                    return true;
                }
                this.transitionAnimationPreviewMode = preview;
                this.transitionAnimationStartTime = System.currentTimeMillis();
                this.transitionAnimationInProgress = true;
                this.onOpenAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$dq-BImQkBZGC18WGtyezCmZmsIk
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$presentFragment$1$ActionBarLayout(preview, removeLast, currentFragment, fragment);
                    }
                };
                if (currentFragment == null) {
                    z = false;
                } else {
                    z = false;
                    currentFragment.onTransitionAnimationStart(false, false);
                }
                fragment.onTransitionAnimationStart(true, z);
                AnimatorSet animation = null;
                if (!preview) {
                    animation = fragment.onCustomTransitionAnimation(true, new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$rCYkVUwyACUH4I_2P11tAf4R1uc
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$presentFragment$2$ActionBarLayout();
                        }
                    });
                }
                if (animation == null) {
                    this.containerView.setAlpha(0.0f);
                    if (preview) {
                        this.containerView.setTranslationX(0.0f);
                        this.containerView.setScaleX(0.9f);
                        this.containerView.setScaleY(0.9f);
                    } else {
                        this.containerView.setTranslationX(48.0f);
                        this.containerView.setScaleX(1.0f);
                        this.containerView.setScaleY(1.0f);
                    }
                    if (this.containerView.isKeyboardVisible || this.containerViewBack.isKeyboardVisible) {
                        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.6
                            @Override // java.lang.Runnable
                            public void run() {
                                if (ActionBarLayout.this.waitingForKeyboardCloseRunnable == this) {
                                    ActionBarLayout.this.waitingForKeyboardCloseRunnable = null;
                                    ActionBarLayout.this.startLayoutAnimation(true, true, preview);
                                }
                            }
                        };
                        this.waitingForKeyboardCloseRunnable = runnable;
                        AndroidUtilities.runOnUIThread(runnable, 200L);
                        return true;
                    }
                    if (fragment.needDelayOpenAnimation()) {
                        Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.7
                            @Override // java.lang.Runnable
                            public void run() {
                                if (ActionBarLayout.this.delayedOpenAnimationRunnable == this) {
                                    ActionBarLayout.this.delayedOpenAnimationRunnable = null;
                                    ActionBarLayout.this.startLayoutAnimation(true, true, preview);
                                }
                            }
                        };
                        this.delayedOpenAnimationRunnable = runnable2;
                        AndroidUtilities.runOnUIThread(runnable2, 200L);
                        return true;
                    }
                    startLayoutAnimation(true, true, preview);
                    return true;
                }
                this.containerView.setAlpha(1.0f);
                this.containerView.setTranslationX(0.0f);
                this.currentAnimation = animation;
                return true;
            }
            View view3 = this.backgroundView;
            if (view3 != null) {
                view3.setAlpha(1.0f);
                this.backgroundView.setVisibility(0);
            }
            if (currentFragment != null) {
                currentFragment.onTransitionAnimationStart(false, false);
                currentFragment.onTransitionAnimationEnd(false, false);
            }
            fragment.onTransitionAnimationStart(true, false);
            fragment.onTransitionAnimationEnd(true, false);
            fragment.onBecomeFullyVisible();
            return true;
        }
        return false;
    }

    static /* synthetic */ void lambda$presentFragment$0(BaseFragment currentFragment, BaseFragment fragment) {
        if (currentFragment != null) {
            currentFragment.onTransitionAnimationEnd(false, false);
        }
        fragment.onTransitionAnimationEnd(true, false);
        fragment.onBecomeFullyVisible();
    }

    public /* synthetic */ void lambda$presentFragment$1$ActionBarLayout(boolean preview, boolean removeLast, BaseFragment currentFragment, BaseFragment fragment) {
        if (preview) {
            this.inPreviewMode = true;
            this.transitionAnimationPreviewMode = false;
            this.containerView.setScaleX(1.0f);
            this.containerView.setScaleY(1.0f);
        } else {
            presentFragmentInternalRemoveOld(removeLast, currentFragment);
            this.containerView.setTranslationX(0.0f);
        }
        if (currentFragment != null) {
            currentFragment.onTransitionAnimationEnd(false, false);
        }
        fragment.onTransitionAnimationEnd(true, false);
        fragment.onBecomeFullyVisible();
    }

    public /* synthetic */ void lambda$presentFragment$2$ActionBarLayout() {
        onAnimationEndCheck(false);
    }

    public boolean presentFragmentFromBottom(final BaseFragment fragment, final boolean removeLast, boolean forceWithoutAnimation, boolean check, final boolean preview) {
        BaseFragment baseFragment;
        View fragmentView;
        boolean z;
        boolean z2;
        if (!checkTransitionAnimation()) {
            ActionBarLayoutDelegate actionBarLayoutDelegate = this.delegate;
            if ((actionBarLayoutDelegate != null && check && !actionBarLayoutDelegate.needPresentFragment(fragment, removeLast, forceWithoutAnimation, this)) || !fragment.onFragmentCreate()) {
                return false;
            }
            fragment.setInPreviewMode(preview);
            if (this.parentActivity.getCurrentFocus() != null) {
                AndroidUtilities.hideKeyboard(this.parentActivity.getCurrentFocus());
            }
            boolean needAnimation = preview || (!forceWithoutAnimation && MessagesController.getGlobalMainSettings().getBoolean("view_animations", true));
            if (this.fragmentsStack.isEmpty()) {
                baseFragment = null;
            } else {
                ArrayList<BaseFragment> arrayList = this.fragmentsStack;
                baseFragment = arrayList.get(arrayList.size() - 1);
            }
            final BaseFragment currentFragment = baseFragment;
            fragment.setParentLayout(this);
            View fragmentView2 = fragment.fragmentView;
            if (fragmentView2 == null) {
                fragmentView = fragment.createView(this.parentActivity);
            } else {
                ViewGroup parent = (ViewGroup) fragmentView2.getParent();
                if (parent != null) {
                    fragment.onRemoveFromParent();
                    parent.removeView(fragmentView2);
                }
                fragmentView = fragmentView2;
            }
            if (fragment.actionBar != null && fragment.actionBar.getAddToContainer()) {
                if (this.removeActionBarExtraHeight) {
                    fragment.actionBar.setOccupyStatusBar(false);
                }
                ViewGroup parent2 = (ViewGroup) fragment.actionBar.getParent();
                if (parent2 != null) {
                    parent2.removeView(fragment.actionBar);
                }
                this.containerViewBack.addView(fragment.actionBar);
                fragment.actionBar.setTitleOverlayText(this.titleOverlayText, this.titleOverlayTextId, this.overlayAction);
            }
            this.containerViewBack.addView(fragmentView);
            LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) fragmentView.getLayoutParams();
            layoutParams.width = -1;
            layoutParams.height = -1;
            if (preview) {
                int iDp = AndroidUtilities.dp(8.0f);
                layoutParams.leftMargin = iDp;
                layoutParams.rightMargin = iDp;
                int iDp2 = AndroidUtilities.dp(46.0f);
                layoutParams.bottomMargin = iDp2;
                layoutParams.topMargin = iDp2;
                layoutParams.topMargin += AndroidUtilities.statusBarHeight;
            } else {
                layoutParams.leftMargin = 0;
                layoutParams.rightMargin = 0;
                layoutParams.bottomMargin = 0;
                layoutParams.topMargin = 0;
            }
            fragmentView.setLayoutParams(layoutParams);
            this.fragmentsStack.add(fragment);
            fragment.onResume();
            this.currentActionBar = fragment.actionBar;
            if (!fragment.hasOwnBackground && fragmentView.getBackground() == null) {
                fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            LinearLayoutContainer temp = this.containerView;
            LinearLayoutContainer linearLayoutContainer = this.containerViewBack;
            this.containerView = linearLayoutContainer;
            this.containerViewBack = temp;
            linearLayoutContainer.setVisibility(0);
            setInnerTranslationX(0.0f);
            this.containerView.setTranslationY(0.0f);
            if (preview) {
                if (Build.VERSION.SDK_INT >= 21) {
                    fragmentView.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.8
                        @Override // android.view.ViewOutlineProvider
                        public void getOutline(View view, Outline outline) {
                            outline.setRoundRect(0, AndroidUtilities.statusBarHeight, view.getMeasuredWidth(), view.getMeasuredHeight(), AndroidUtilities.dp(6.0f));
                        }
                    });
                    fragmentView.setClipToOutline(true);
                    fragmentView.setElevation(AndroidUtilities.dp(4.0f));
                }
                if (this.previewBackgroundDrawable == null) {
                    this.previewBackgroundDrawable = new ColorDrawable(Integer.MIN_VALUE);
                }
                this.previewBackgroundDrawable.setAlpha(0);
                Theme.moveUpDrawable.setAlpha(0);
            }
            bringChildToFront(this.containerView);
            if (!needAnimation) {
                presentFragmentInternalRemoveOld(removeLast, currentFragment);
                View view = this.backgroundView;
                if (view != null) {
                    view.setVisibility(0);
                }
            }
            if (this.themeAnimatorSet != null) {
                this.presentingFragmentDescriptions = fragment.getThemeDescriptions();
            }
            if (needAnimation || preview) {
                if (this.useAlphaAnimations && this.fragmentsStack.size() == 1) {
                    presentFragmentInternalRemoveOld(removeLast, currentFragment);
                    this.transitionAnimationStartTime = System.currentTimeMillis();
                    this.transitionAnimationInProgress = true;
                    this.onOpenAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$BScnbnVEGbsTKE5Qssfv0vS2Cns
                        @Override // java.lang.Runnable
                        public final void run() {
                            ActionBarLayout.lambda$presentFragmentFromBottom$3(currentFragment, fragment);
                        }
                    };
                    ArrayList<Animator> animators = new ArrayList<>();
                    animators.add(ObjectAnimator.ofFloat(this, "alpha", 0.0f, 1.0f));
                    View view2 = this.backgroundView;
                    if (view2 != null) {
                        view2.setVisibility(0);
                        animators.add(ObjectAnimator.ofFloat(this.backgroundView, "alpha", 0.0f, 1.0f));
                    }
                    if (currentFragment == null) {
                        z2 = false;
                    } else {
                        z2 = false;
                        currentFragment.onTransitionAnimationStart(false, false);
                    }
                    fragment.onTransitionAnimationStart(true, z2);
                    AnimatorSet animatorSet = new AnimatorSet();
                    this.currentAnimation = animatorSet;
                    animatorSet.playTogether(animators);
                    this.currentAnimation.setInterpolator(this.accelerateDecelerateInterpolator);
                    this.currentAnimation.setDuration(200L);
                    this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.9
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            ActionBarLayout.this.onAnimationEndCheck(false);
                        }
                    });
                    this.currentAnimation.start();
                    return true;
                }
                this.transitionAnimationPreviewMode = preview;
                this.transitionAnimationStartTime = System.currentTimeMillis();
                this.transitionAnimationInProgress = true;
                this.onOpenAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$5b-OIHcZDbHlavwf7IJL1jMOijg
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$presentFragmentFromBottom$4$ActionBarLayout(preview, removeLast, currentFragment, fragment);
                    }
                };
                if (currentFragment == null) {
                    z = false;
                } else {
                    z = false;
                    currentFragment.onTransitionAnimationStart(false, false);
                }
                fragment.onTransitionAnimationStart(true, z);
                AnimatorSet animation = null;
                if (!preview) {
                    animation = fragment.onCustomTransitionAnimation(true, new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$bMF0_-Hq-UJFHNBlWrKvs08-awI
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$presentFragmentFromBottom$5$ActionBarLayout();
                        }
                    });
                }
                if (animation == null) {
                    this.containerView.setAlpha(0.0f);
                    if (preview) {
                        this.containerView.setTranslationX(0.0f);
                        this.containerView.setScaleX(0.9f);
                        this.containerView.setScaleY(0.9f);
                    } else {
                        this.containerView.setTranslationY(48.0f);
                        this.containerView.setScaleX(1.0f);
                        this.containerView.setScaleY(1.0f);
                    }
                    if (this.containerView.isKeyboardVisible || this.containerViewBack.isKeyboardVisible) {
                        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.10
                            @Override // java.lang.Runnable
                            public void run() {
                                if (ActionBarLayout.this.waitingForKeyboardCloseRunnable == this) {
                                    ActionBarLayout.this.waitingForKeyboardCloseRunnable = null;
                                    ActionBarLayout.this.startLayoutAnimationFromBottom(true, true, preview);
                                }
                            }
                        };
                        this.waitingForKeyboardCloseRunnable = runnable;
                        AndroidUtilities.runOnUIThread(runnable, 200L);
                        return true;
                    }
                    if (fragment.needDelayOpenAnimation()) {
                        Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.11
                            @Override // java.lang.Runnable
                            public void run() {
                                if (ActionBarLayout.this.delayedOpenAnimationRunnable == this) {
                                    ActionBarLayout.this.delayedOpenAnimationRunnable = null;
                                    ActionBarLayout.this.startLayoutAnimationFromBottom(true, true, preview);
                                }
                            }
                        };
                        this.delayedOpenAnimationRunnable = runnable2;
                        AndroidUtilities.runOnUIThread(runnable2, 200L);
                        return true;
                    }
                    startLayoutAnimationFromBottom(true, true, preview);
                    return true;
                }
                this.containerView.setAlpha(1.0f);
                this.containerView.setTranslationX(0.0f);
                this.currentAnimation = animation;
                return true;
            }
            View view3 = this.backgroundView;
            if (view3 != null) {
                view3.setAlpha(1.0f);
                this.backgroundView.setVisibility(0);
            }
            if (currentFragment != null) {
                currentFragment.onTransitionAnimationStart(false, false);
                currentFragment.onTransitionAnimationEnd(false, false);
            }
            fragment.onTransitionAnimationStart(true, false);
            fragment.onTransitionAnimationEnd(true, false);
            fragment.onBecomeFullyVisible();
            return true;
        }
        return false;
    }

    static /* synthetic */ void lambda$presentFragmentFromBottom$3(BaseFragment currentFragment, BaseFragment fragment) {
        if (currentFragment != null) {
            currentFragment.onTransitionAnimationEnd(false, false);
        }
        fragment.onTransitionAnimationEnd(true, false);
        fragment.onBecomeFullyVisible();
    }

    public /* synthetic */ void lambda$presentFragmentFromBottom$4$ActionBarLayout(boolean preview, boolean removeLast, BaseFragment currentFragment, BaseFragment fragment) {
        if (preview) {
            this.inPreviewMode = true;
            this.transitionAnimationPreviewMode = false;
            this.containerView.setScaleX(1.0f);
            this.containerView.setScaleY(1.0f);
        } else {
            presentFragmentInternalRemoveOld(removeLast, currentFragment);
            this.containerView.setTranslationX(0.0f);
        }
        if (currentFragment != null) {
            currentFragment.onTransitionAnimationEnd(false, false);
        }
        fragment.onTransitionAnimationEnd(true, false);
        fragment.onBecomeFullyVisible();
    }

    public /* synthetic */ void lambda$presentFragmentFromBottom$5$ActionBarLayout() {
        onAnimationEndCheck(false);
    }

    public boolean addFragmentToStack(BaseFragment fragment) {
        return addFragmentToStack(fragment, -1);
    }

    public boolean addFragmentToStack(BaseFragment fragment, int position) {
        ViewGroup parent;
        ViewGroup parent2;
        ActionBarLayoutDelegate actionBarLayoutDelegate = this.delegate;
        if ((actionBarLayoutDelegate != null && !actionBarLayoutDelegate.needAddFragmentToStack(fragment, this)) || !fragment.onFragmentCreate()) {
            return false;
        }
        fragment.setParentLayout(this);
        if (position == -1) {
            if (!this.fragmentsStack.isEmpty()) {
                ArrayList<BaseFragment> arrayList = this.fragmentsStack;
                BaseFragment previousFragment = arrayList.get(arrayList.size() - 1);
                previousFragment.onPause();
                if (previousFragment.actionBar != null && previousFragment.actionBar.getAddToContainer() && (parent2 = (ViewGroup) previousFragment.actionBar.getParent()) != null) {
                    parent2.removeView(previousFragment.actionBar);
                }
                if (previousFragment.fragmentView != null && (parent = (ViewGroup) previousFragment.fragmentView.getParent()) != null) {
                    previousFragment.onRemoveFromParent();
                    parent.removeView(previousFragment.fragmentView);
                }
            }
            this.fragmentsStack.add(fragment);
        } else {
            this.fragmentsStack.add(position, fragment);
        }
        return true;
    }

    private void closeLastFragmentInternalRemoveOld(BaseFragment fragment) {
        fragment.onPause();
        fragment.onFragmentDestroy();
        fragment.setParentLayout(null);
        this.fragmentsStack.remove(fragment);
        this.containerViewBack.setVisibility(8);
        bringChildToFront(this.containerView);
    }

    public void movePreviewFragment(float dy) {
        if (this.inPreviewMode && !this.transitionAnimationPreviewMode) {
            float currentTranslation = this.containerView.getTranslationY();
            float nextTranslation = -dy;
            if (nextTranslation > 0.0f) {
                nextTranslation = 0.0f;
            } else if (nextTranslation < (-AndroidUtilities.dp(60.0f))) {
                this.inPreviewMode = false;
                nextTranslation = 0.0f;
                ArrayList<BaseFragment> arrayList = this.fragmentsStack;
                BaseFragment prevFragment = arrayList.get(arrayList.size() - 2);
                ArrayList<BaseFragment> arrayList2 = this.fragmentsStack;
                BaseFragment fragment = arrayList2.get(arrayList2.size() - 1);
                if (Build.VERSION.SDK_INT >= 21) {
                    fragment.fragmentView.setOutlineProvider(null);
                    fragment.fragmentView.setClipToOutline(false);
                }
                LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) fragment.fragmentView.getLayoutParams();
                layoutParams.leftMargin = 0;
                layoutParams.rightMargin = 0;
                layoutParams.bottomMargin = 0;
                layoutParams.topMargin = 0;
                fragment.fragmentView.setLayoutParams(layoutParams);
                presentFragmentInternalRemoveOld(false, prevFragment);
                AnimatorSet animatorSet = new AnimatorSet();
                animatorSet.playTogether(ObjectAnimator.ofFloat(fragment.fragmentView, "scaleX", 1.0f, 1.05f, 1.0f), ObjectAnimator.ofFloat(fragment.fragmentView, "scaleY", 1.0f, 1.05f, 1.0f));
                animatorSet.setDuration(200L);
                animatorSet.setInterpolator(new CubicBezierInterpolator(0.42d, FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE, 0.58d, 1.0d));
                animatorSet.start();
                performHapticFeedback(3);
                fragment.setInPreviewMode(false);
            }
            if (currentTranslation != nextTranslation) {
                this.containerView.setTranslationY(nextTranslation);
                invalidate();
            }
        }
    }

    public void finishPreviewFragment() {
        if (!this.inPreviewMode && !this.transitionAnimationPreviewMode) {
            return;
        }
        closeLastFragment(true);
    }

    public void closeLastFragment(boolean animated) {
        ActionBarLayoutDelegate actionBarLayoutDelegate = this.delegate;
        if ((actionBarLayoutDelegate != null && !actionBarLayoutDelegate.needCloseLastFragment(this)) || checkTransitionAnimation() || this.fragmentsStack.isEmpty()) {
            return;
        }
        if (this.parentActivity.getCurrentFocus() != null) {
            AndroidUtilities.hideKeyboard(this.parentActivity.getCurrentFocus());
        }
        setInnerTranslationX(0.0f);
        boolean needAnimation = this.inPreviewMode || this.transitionAnimationPreviewMode || (animated && MessagesController.getGlobalMainSettings().getBoolean("view_animations", true));
        ArrayList<BaseFragment> arrayList = this.fragmentsStack;
        final BaseFragment currentFragment = arrayList.get(arrayList.size() - 1);
        BaseFragment previousFragment = null;
        if (this.fragmentsStack.size() > 1) {
            ArrayList<BaseFragment> arrayList2 = this.fragmentsStack;
            BaseFragment previousFragment2 = arrayList2.get(arrayList2.size() - 2);
            previousFragment = previousFragment2;
        }
        if (previousFragment != null) {
            LinearLayoutContainer temp = this.containerView;
            this.containerView = this.containerViewBack;
            this.containerViewBack = temp;
            previousFragment.setParentLayout(this);
            View fragmentView = previousFragment.fragmentView;
            if (fragmentView == null) {
                fragmentView = previousFragment.createView(this.parentActivity);
            }
            if (!this.inPreviewMode) {
                this.containerView.setVisibility(0);
                if (previousFragment.actionBar != null && previousFragment.actionBar.getAddToContainer()) {
                    if (this.removeActionBarExtraHeight) {
                        previousFragment.actionBar.setOccupyStatusBar(false);
                    }
                    ViewGroup parent = (ViewGroup) previousFragment.actionBar.getParent();
                    if (parent != null) {
                        parent.removeView(previousFragment.actionBar);
                    }
                    this.containerView.addView(previousFragment.actionBar);
                    previousFragment.actionBar.setTitleOverlayText(this.titleOverlayText, this.titleOverlayTextId, this.overlayAction);
                }
                ViewGroup parent2 = (ViewGroup) fragmentView.getParent();
                if (parent2 != null) {
                    previousFragment.onRemoveFromParent();
                    try {
                        parent2.removeView(fragmentView);
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                }
                this.containerView.addView(fragmentView);
                LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) fragmentView.getLayoutParams();
                layoutParams.width = -1;
                layoutParams.height = -1;
                layoutParams.leftMargin = 0;
                layoutParams.rightMargin = 0;
                layoutParams.bottomMargin = 0;
                layoutParams.topMargin = 0;
                fragmentView.setLayoutParams(layoutParams);
            }
            previousFragment.onTransitionAnimationStart(true, true);
            currentFragment.onTransitionAnimationStart(false, true);
            previousFragment.onResume();
            if (this.themeAnimatorSet != null) {
                this.presentingFragmentDescriptions = previousFragment.getThemeDescriptions();
            }
            this.currentActionBar = previousFragment.actionBar;
            if (!previousFragment.hasOwnBackground && fragmentView.getBackground() == null) {
                fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            if (!needAnimation) {
                closeLastFragmentInternalRemoveOld(currentFragment);
            }
            if (needAnimation) {
                this.transitionAnimationStartTime = System.currentTimeMillis();
                this.transitionAnimationInProgress = true;
                final BaseFragment previousFragmentFinal = previousFragment;
                this.onCloseAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$YuXOE2ZXe8D1n4YU3GHj4f-nR9k
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$closeLastFragment$6$ActionBarLayout(currentFragment, previousFragmentFinal);
                    }
                };
                AnimatorSet animation = null;
                if (!this.inPreviewMode && !this.transitionAnimationPreviewMode) {
                    animation = currentFragment.onCustomTransitionAnimation(false, new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$7K7RdHNXn_oh-f3J_SLeH6l4IPI
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$closeLastFragment$7$ActionBarLayout();
                        }
                    });
                }
                if (animation == null) {
                    if (this.containerView.isKeyboardVisible || this.containerViewBack.isKeyboardVisible) {
                        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.12
                            @Override // java.lang.Runnable
                            public void run() {
                                if (ActionBarLayout.this.waitingForKeyboardCloseRunnable == this) {
                                    ActionBarLayout.this.waitingForKeyboardCloseRunnable = null;
                                    ActionBarLayout.this.startLayoutAnimation(false, true, false);
                                }
                            }
                        };
                        this.waitingForKeyboardCloseRunnable = runnable;
                        AndroidUtilities.runOnUIThread(runnable, 200L);
                        return;
                    }
                    startLayoutAnimation(false, true, this.inPreviewMode || this.transitionAnimationPreviewMode);
                    return;
                }
                this.currentAnimation = animation;
                return;
            }
            currentFragment.onTransitionAnimationEnd(false, true);
            previousFragment.onTransitionAnimationEnd(true, true);
            previousFragment.onBecomeFullyVisible();
            return;
        }
        if (this.useAlphaAnimations) {
            this.transitionAnimationStartTime = System.currentTimeMillis();
            this.transitionAnimationInProgress = true;
            this.onCloseAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$odQKoL20gRa9qESZKHCFpcHwJHM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$closeLastFragment$8$ActionBarLayout(currentFragment);
                }
            };
            ArrayList<Animator> animators = new ArrayList<>();
            animators.add(ObjectAnimator.ofFloat(this, "alpha", 1.0f, 0.0f));
            View view = this.backgroundView;
            if (view != null) {
                animators.add(ObjectAnimator.ofFloat(view, "alpha", 1.0f, 0.0f));
            }
            AnimatorSet animatorSet = new AnimatorSet();
            this.currentAnimation = animatorSet;
            animatorSet.playTogether(animators);
            this.currentAnimation.setInterpolator(this.accelerateDecelerateInterpolator);
            this.currentAnimation.setDuration(200L);
            this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.13
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationStart(Animator animation2) {
                    ActionBarLayout.this.transitionAnimationStartTime = System.currentTimeMillis();
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation2) {
                    ActionBarLayout.this.onAnimationEndCheck(false);
                }
            });
            this.currentAnimation.start();
            return;
        }
        removeFragmentFromStackInternal(currentFragment);
        setVisibility(8);
        View view2 = this.backgroundView;
        if (view2 != null) {
            view2.setVisibility(8);
        }
    }

    public /* synthetic */ void lambda$closeLastFragment$6$ActionBarLayout(BaseFragment currentFragment, BaseFragment previousFragmentFinal) {
        if (this.inPreviewMode || this.transitionAnimationPreviewMode) {
            this.containerViewBack.setScaleX(1.0f);
            this.containerViewBack.setScaleY(1.0f);
            this.inPreviewMode = false;
            this.transitionAnimationPreviewMode = false;
        } else {
            this.containerViewBack.setTranslationX(0.0f);
        }
        closeLastFragmentInternalRemoveOld(currentFragment);
        currentFragment.onTransitionAnimationEnd(false, true);
        previousFragmentFinal.onTransitionAnimationEnd(true, true);
        previousFragmentFinal.onBecomeFullyVisible();
    }

    public /* synthetic */ void lambda$closeLastFragment$7$ActionBarLayout() {
        onAnimationEndCheck(false);
    }

    public /* synthetic */ void lambda$closeLastFragment$8$ActionBarLayout(BaseFragment currentFragment) {
        removeFragmentFromStackInternal(currentFragment);
        setVisibility(8);
        View view = this.backgroundView;
        if (view != null) {
            view.setVisibility(8);
        }
        DrawerLayoutContainer drawerLayoutContainer = this.drawerLayoutContainer;
        if (drawerLayoutContainer != null) {
            drawerLayoutContainer.setAllowOpenDrawer(false, false);
        }
    }

    public void closeLastFragmentFromUp(boolean animated) {
        ActionBarLayoutDelegate actionBarLayoutDelegate = this.delegate;
        if ((actionBarLayoutDelegate != null && !actionBarLayoutDelegate.needCloseLastFragment(this)) || checkTransitionAnimation() || this.fragmentsStack.isEmpty()) {
            return;
        }
        if (this.parentActivity.getCurrentFocus() != null) {
            AndroidUtilities.hideKeyboard(this.parentActivity.getCurrentFocus());
        }
        setInnerTranslationX(0.0f);
        boolean needAnimation = this.inPreviewMode || this.transitionAnimationPreviewMode || (animated && MessagesController.getGlobalMainSettings().getBoolean("view_animations", true));
        ArrayList<BaseFragment> arrayList = this.fragmentsStack;
        final BaseFragment currentFragment = arrayList.get(arrayList.size() - 1);
        BaseFragment previousFragment = null;
        if (this.fragmentsStack.size() > 1) {
            ArrayList<BaseFragment> arrayList2 = this.fragmentsStack;
            BaseFragment previousFragment2 = arrayList2.get(arrayList2.size() - 2);
            previousFragment = previousFragment2;
        }
        if (previousFragment != null) {
            LinearLayoutContainer temp = this.containerView;
            this.containerView = this.containerViewBack;
            this.containerViewBack = temp;
            previousFragment.setParentLayout(this);
            View fragmentView = previousFragment.fragmentView;
            if (fragmentView == null) {
                fragmentView = previousFragment.createView(this.parentActivity);
            }
            if (!this.inPreviewMode) {
                this.containerView.setVisibility(0);
                if (previousFragment.actionBar != null && previousFragment.actionBar.getAddToContainer()) {
                    if (this.removeActionBarExtraHeight) {
                        previousFragment.actionBar.setOccupyStatusBar(false);
                    }
                    ViewGroup parent = (ViewGroup) previousFragment.actionBar.getParent();
                    if (parent != null) {
                        parent.removeView(previousFragment.actionBar);
                    }
                    this.containerView.addView(previousFragment.actionBar);
                    previousFragment.actionBar.setTitleOverlayText(this.titleOverlayText, this.titleOverlayTextId, this.overlayAction);
                }
                ViewGroup parent2 = (ViewGroup) fragmentView.getParent();
                if (parent2 != null) {
                    previousFragment.onRemoveFromParent();
                    try {
                        parent2.removeView(fragmentView);
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                }
                this.containerView.addView(fragmentView);
                LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) fragmentView.getLayoutParams();
                layoutParams.width = -1;
                layoutParams.height = -1;
                layoutParams.leftMargin = 0;
                layoutParams.rightMargin = 0;
                layoutParams.bottomMargin = 0;
                layoutParams.topMargin = 0;
                fragmentView.setLayoutParams(layoutParams);
            }
            previousFragment.onTransitionAnimationStart(true, true);
            currentFragment.onTransitionAnimationStart(false, true);
            previousFragment.onResume();
            if (this.themeAnimatorSet != null) {
                this.presentingFragmentDescriptions = previousFragment.getThemeDescriptions();
            }
            this.currentActionBar = previousFragment.actionBar;
            if (!previousFragment.hasOwnBackground && fragmentView.getBackground() == null) {
                fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            if (!needAnimation) {
                closeLastFragmentInternalRemoveOld(currentFragment);
            }
            if (needAnimation) {
                this.transitionAnimationStartTime = System.currentTimeMillis();
                this.transitionAnimationInProgress = true;
                final BaseFragment previousFragmentFinal = previousFragment;
                this.onCloseAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$h5JPGc7OpQPyy58pkw7lkCgwVtw
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$closeLastFragmentFromUp$9$ActionBarLayout(currentFragment, previousFragmentFinal);
                    }
                };
                AnimatorSet animation = null;
                if (!this.inPreviewMode && !this.transitionAnimationPreviewMode) {
                    animation = currentFragment.onCustomTransitionAnimation(false, new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$gzVfHrTVzI7-OHXRA0gZz2SnMvY
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$closeLastFragmentFromUp$10$ActionBarLayout();
                        }
                    });
                }
                if (animation == null) {
                    if (this.containerView.isKeyboardVisible || this.containerViewBack.isKeyboardVisible) {
                        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.14
                            @Override // java.lang.Runnable
                            public void run() {
                                if (ActionBarLayout.this.waitingForKeyboardCloseRunnable == this) {
                                    ActionBarLayout.this.waitingForKeyboardCloseRunnable = null;
                                    ActionBarLayout.this.startLayoutAnimationFromBottom(false, true, false);
                                }
                            }
                        };
                        this.waitingForKeyboardCloseRunnable = runnable;
                        AndroidUtilities.runOnUIThread(runnable, 200L);
                        return;
                    }
                    startLayoutAnimationFromBottom(false, true, this.inPreviewMode || this.transitionAnimationPreviewMode);
                    return;
                }
                this.currentAnimation = animation;
                return;
            }
            currentFragment.onTransitionAnimationEnd(false, true);
            previousFragment.onTransitionAnimationEnd(true, true);
            previousFragment.onBecomeFullyVisible();
            return;
        }
        if (this.useAlphaAnimations) {
            this.transitionAnimationStartTime = System.currentTimeMillis();
            this.transitionAnimationInProgress = true;
            this.onCloseAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$slRBr4yf-WHy4e4yOfewD3Iq0fs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$closeLastFragmentFromUp$11$ActionBarLayout(currentFragment);
                }
            };
            ArrayList<Animator> animators = new ArrayList<>();
            animators.add(ObjectAnimator.ofFloat(this, "alpha", 1.0f, 0.0f));
            View view = this.backgroundView;
            if (view != null) {
                animators.add(ObjectAnimator.ofFloat(view, "alpha", 1.0f, 0.0f));
            }
            AnimatorSet animatorSet = new AnimatorSet();
            this.currentAnimation = animatorSet;
            animatorSet.playTogether(animators);
            this.currentAnimation.setInterpolator(this.accelerateDecelerateInterpolator);
            this.currentAnimation.setDuration(200L);
            this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.15
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationStart(Animator animation2) {
                    ActionBarLayout.this.transitionAnimationStartTime = System.currentTimeMillis();
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation2) {
                    ActionBarLayout.this.onAnimationEndCheck(false);
                }
            });
            this.currentAnimation.start();
            return;
        }
        removeFragmentFromStackInternal(currentFragment);
        setVisibility(8);
        View view2 = this.backgroundView;
        if (view2 != null) {
            view2.setVisibility(8);
        }
    }

    public /* synthetic */ void lambda$closeLastFragmentFromUp$9$ActionBarLayout(BaseFragment currentFragment, BaseFragment previousFragmentFinal) {
        if (this.inPreviewMode || this.transitionAnimationPreviewMode) {
            this.containerViewBack.setScaleX(1.0f);
            this.containerViewBack.setScaleY(1.0f);
            this.inPreviewMode = false;
            this.transitionAnimationPreviewMode = false;
        } else {
            this.containerViewBack.setTranslationY(0.0f);
        }
        closeLastFragmentInternalRemoveOld(currentFragment);
        currentFragment.onTransitionAnimationEnd(false, true);
        previousFragmentFinal.onTransitionAnimationEnd(true, true);
        previousFragmentFinal.onBecomeFullyVisible();
    }

    public /* synthetic */ void lambda$closeLastFragmentFromUp$10$ActionBarLayout() {
        onAnimationEndCheck(false);
    }

    public /* synthetic */ void lambda$closeLastFragmentFromUp$11$ActionBarLayout(BaseFragment currentFragment) {
        removeFragmentFromStackInternal(currentFragment);
        setVisibility(8);
        View view = this.backgroundView;
        if (view != null) {
            view.setVisibility(8);
        }
        DrawerLayoutContainer drawerLayoutContainer = this.drawerLayoutContainer;
        if (drawerLayoutContainer != null) {
            drawerLayoutContainer.setAllowOpenDrawer(false, false);
        }
    }

    public void showLastFragment() {
        ViewGroup parent;
        ViewGroup parent2;
        if (this.fragmentsStack.isEmpty()) {
            return;
        }
        for (int a = 0; a < this.fragmentsStack.size() - 1; a++) {
            BaseFragment previousFragment = this.fragmentsStack.get(a);
            if (previousFragment.actionBar != null && previousFragment.actionBar.getAddToContainer() && (parent2 = (ViewGroup) previousFragment.actionBar.getParent()) != null) {
                parent2.removeView(previousFragment.actionBar);
            }
            if (previousFragment.fragmentView != null && (parent = (ViewGroup) previousFragment.fragmentView.getParent()) != null) {
                previousFragment.onPause();
                previousFragment.onRemoveFromParent();
                parent.removeView(previousFragment.fragmentView);
            }
        }
        BaseFragment previousFragment2 = this.fragmentsStack.get(r0.size() - 1);
        previousFragment2.setParentLayout(this);
        View fragmentView = previousFragment2.fragmentView;
        if (fragmentView == null) {
            fragmentView = previousFragment2.createView(this.parentActivity);
        } else {
            ViewGroup parent3 = (ViewGroup) fragmentView.getParent();
            if (parent3 != null) {
                previousFragment2.onRemoveFromParent();
                parent3.removeView(fragmentView);
            }
        }
        if (previousFragment2.actionBar != null && previousFragment2.actionBar.getAddToContainer()) {
            if (this.removeActionBarExtraHeight) {
                previousFragment2.actionBar.setOccupyStatusBar(false);
            }
            ViewGroup parent4 = (ViewGroup) previousFragment2.actionBar.getParent();
            if (parent4 != null) {
                parent4.removeView(previousFragment2.actionBar);
            }
            this.containerView.addView(previousFragment2.actionBar);
            previousFragment2.actionBar.setTitleOverlayText(this.titleOverlayText, this.titleOverlayTextId, this.overlayAction);
        }
        this.containerView.addView(fragmentView, LayoutHelper.createLinear(-1, -1));
        previousFragment2.onResume();
        this.currentActionBar = previousFragment2.actionBar;
        if (!previousFragment2.hasOwnBackground && fragmentView.getBackground() == null) {
            fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        }
    }

    private void removeFragmentFromStackInternal(BaseFragment fragment) {
        fragment.onPause();
        fragment.onFragmentDestroy();
        fragment.setParentLayout(null);
        this.fragmentsStack.remove(fragment);
    }

    public void removeFragmentFromStack(int num) {
        if (num >= this.fragmentsStack.size()) {
            return;
        }
        removeFragmentFromStackInternal(this.fragmentsStack.get(num));
    }

    public void removeFragmentFromStack(BaseFragment fragment) {
        if (this.useAlphaAnimations && this.fragmentsStack.size() == 1 && AndroidUtilities.isTablet()) {
            closeLastFragment(true);
        } else {
            removeFragmentFromStackInternal(fragment);
        }
    }

    public void removeAllFragments() {
        for (int a = 0; a < this.fragmentsStack.size(); a = (a - 1) + 1) {
            removeFragmentFromStackInternal(this.fragmentsStack.get(a));
        }
    }

    public void setThemeAnimationValue(float value) {
        float f = value;
        this.themeAnimationValue = f;
        int j = 0;
        while (j < 2) {
            if (this.themeAnimatorDescriptions[j] != null) {
                int i = 0;
                while (i < this.themeAnimatorDescriptions[j].length) {
                    int rE = Color.red(this.animateEndColors[j][i]);
                    int gE = Color.green(this.animateEndColors[j][i]);
                    int bE = Color.blue(this.animateEndColors[j][i]);
                    int aE = Color.alpha(this.animateEndColors[j][i]);
                    int rS = Color.red(this.animateStartColors[j][i]);
                    int gS = Color.green(this.animateStartColors[j][i]);
                    int bS = Color.blue(this.animateStartColors[j][i]);
                    int aS = Color.alpha(this.animateStartColors[j][i]);
                    int a = Math.min(255, (int) (aS + ((aE - aS) * f)));
                    int r = Math.min(255, (int) (rS + ((rE - rS) * f)));
                    int g = Math.min(255, (int) (gS + ((gE - gS) * f)));
                    int rE2 = bE - bS;
                    int b = Math.min(255, (int) (bS + (rE2 * f)));
                    int color = Color.argb(a, r, g, b);
                    Theme.setAnimatedColor(this.themeAnimatorDescriptions[j][i].getCurrentKey(), color);
                    this.themeAnimatorDescriptions[j][i].setColor(color, false, false);
                    i++;
                    f = value;
                }
                ThemeDescription.ThemeDescriptionDelegate[] themeDescriptionDelegateArr = this.themeAnimatorDelegate;
                if (themeDescriptionDelegateArr[j] != null) {
                    themeDescriptionDelegateArr[j].didSetColor();
                }
            }
            j++;
            f = value;
        }
        if (this.presentingFragmentDescriptions != null) {
            int i2 = 0;
            while (true) {
                ThemeDescription[] themeDescriptionArr = this.presentingFragmentDescriptions;
                if (i2 < themeDescriptionArr.length) {
                    String key = themeDescriptionArr[i2].getCurrentKey();
                    this.presentingFragmentDescriptions[i2].setColor(Theme.getColor(key), false, false);
                    i2++;
                } else {
                    return;
                }
            }
        }
    }

    public float getThemeAnimationValue() {
        return this.themeAnimationValue;
    }

    public void animateThemedValues(Theme.ThemeInfo theme, boolean nightTheme) {
        BaseFragment fragment;
        if (this.transitionAnimationInProgress || this.startedTracking) {
            this.animateThemeAfterAnimation = true;
            this.animateSetThemeAfterAnimation = theme;
            this.animateSetThemeNightAfterAnimation = nightTheme;
            return;
        }
        AnimatorSet animatorSet = this.themeAnimatorSet;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.themeAnimatorSet = null;
        }
        boolean startAnimation = false;
        for (int i = 0; i < 2; i++) {
            if (i == 0) {
                fragment = getLastFragment();
            } else if ((!this.inPreviewMode && !this.transitionAnimationPreviewMode) || this.fragmentsStack.size() <= 1) {
                this.themeAnimatorDescriptions[i] = null;
                this.animateStartColors[i] = null;
                this.animateEndColors[i] = null;
                this.themeAnimatorDelegate[i] = null;
            } else {
                ArrayList<BaseFragment> arrayList = this.fragmentsStack;
                fragment = arrayList.get(arrayList.size() - 2);
            }
            if (fragment != null) {
                startAnimation = true;
                this.themeAnimatorDescriptions[i] = fragment.getThemeDescriptions();
                this.animateStartColors[i] = new int[this.themeAnimatorDescriptions[i].length];
                int a = 0;
                while (true) {
                    ThemeDescription[][] themeDescriptionArr = this.themeAnimatorDescriptions;
                    if (a >= themeDescriptionArr[i].length) {
                        break;
                    }
                    this.animateStartColors[i][a] = themeDescriptionArr[i][a].getSetColor();
                    ThemeDescription.ThemeDescriptionDelegate delegate = this.themeAnimatorDescriptions[i][a].setDelegateDisabled();
                    ThemeDescription.ThemeDescriptionDelegate[] themeDescriptionDelegateArr = this.themeAnimatorDelegate;
                    if (themeDescriptionDelegateArr[i] == null && delegate != null) {
                        themeDescriptionDelegateArr[i] = delegate;
                    }
                    a++;
                }
                if (i == 0) {
                    Theme.applyTheme(theme, nightTheme);
                }
                this.animateEndColors[i] = new int[this.themeAnimatorDescriptions[i].length];
                int a2 = 0;
                while (true) {
                    ThemeDescription[][] themeDescriptionArr2 = this.themeAnimatorDescriptions;
                    if (a2 < themeDescriptionArr2[i].length) {
                        this.animateEndColors[i][a2] = themeDescriptionArr2[i][a2].getSetColor();
                        a2++;
                    }
                }
            }
        }
        if (startAnimation) {
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.themeAnimatorSet = animatorSet2;
            animatorSet2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.16
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (animation.equals(ActionBarLayout.this.themeAnimatorSet)) {
                        for (int a3 = 0; a3 < 2; a3++) {
                            ActionBarLayout.this.themeAnimatorDescriptions[a3] = null;
                            ActionBarLayout.this.animateStartColors[a3] = null;
                            ActionBarLayout.this.animateEndColors[a3] = null;
                            ActionBarLayout.this.themeAnimatorDelegate[a3] = null;
                        }
                        Theme.setAnimatingColor(false);
                        ActionBarLayout.this.presentingFragmentDescriptions = null;
                        ActionBarLayout.this.themeAnimatorSet = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (animation.equals(ActionBarLayout.this.themeAnimatorSet)) {
                        for (int a3 = 0; a3 < 2; a3++) {
                            ActionBarLayout.this.themeAnimatorDescriptions[a3] = null;
                            ActionBarLayout.this.animateStartColors[a3] = null;
                            ActionBarLayout.this.animateEndColors[a3] = null;
                            ActionBarLayout.this.themeAnimatorDelegate[a3] = null;
                        }
                        Theme.setAnimatingColor(false);
                        ActionBarLayout.this.presentingFragmentDescriptions = null;
                        ActionBarLayout.this.themeAnimatorSet = null;
                    }
                }
            });
            int count = this.fragmentsStack.size() - ((this.inPreviewMode || this.transitionAnimationPreviewMode) ? 2 : 1);
            for (int a3 = 0; a3 < count; a3++) {
                BaseFragment fragment2 = this.fragmentsStack.get(a3);
                fragment2.clearViews();
                fragment2.setParentLayout(this);
                if (this.fragmentsStack.get(a3) instanceof IndexActivity) {
                    ((IndexActivity) this.fragmentsStack.get(a3)).rebuidView();
                }
            }
            Theme.setAnimatingColor(true);
            this.themeAnimatorSet.playTogether(ObjectAnimator.ofFloat(this, "themeAnimationValue", 0.0f, 1.0f));
            this.themeAnimatorSet.setDuration(200L);
            this.themeAnimatorSet.start();
        }
    }

    public void rebuildAllFragmentViews(boolean last, boolean showLastAfter) {
        if (this.transitionAnimationInProgress || this.startedTracking) {
            this.rebuildAfterAnimation = true;
            this.rebuildLastAfterAnimation = last;
            this.showLastAfterAnimation = showLastAfter;
            return;
        }
        int size = this.fragmentsStack.size();
        if (!last) {
            size--;
        }
        if (this.inPreviewMode) {
            size--;
        }
        for (int a = 0; a < size; a++) {
            this.fragmentsStack.get(a).clearViews();
            this.fragmentsStack.get(a).setParentLayout(this);
            if (this.fragmentsStack.get(a) instanceof IndexActivity) {
                ((IndexActivity) this.fragmentsStack.get(a)).rebuidView();
            }
        }
        ActionBarLayoutDelegate actionBarLayoutDelegate = this.delegate;
        if (actionBarLayoutDelegate != null) {
            actionBarLayoutDelegate.onRebuildAllFragments(this, last);
        }
        if (showLastAfter) {
            showLastFragment();
        }
    }

    @Override // android.view.View, android.view.KeyEvent.Callback
    public boolean onKeyUp(int keyCode, KeyEvent event) {
        ActionBar actionBar;
        if (keyCode == 82 && !checkTransitionAnimation() && !this.startedTracking && (actionBar = this.currentActionBar) != null) {
            actionBar.onMenuButtonPressed();
        }
        return super.onKeyUp(keyCode, event);
    }

    public void onActionModeStarted(Object mode) {
        ActionBar actionBar = this.currentActionBar;
        if (actionBar != null) {
            actionBar.setVisibility(8);
        }
        this.inActionMode = true;
    }

    public void onActionModeFinished(Object mode) {
        ActionBar actionBar = this.currentActionBar;
        if (actionBar != null) {
            actionBar.setVisibility(0);
        }
        this.inActionMode = false;
    }

    private void onCloseAnimationEnd() {
        Runnable runnable;
        if (this.transitionAnimationInProgress && (runnable = this.onCloseAnimationEndRunnable) != null) {
            this.transitionAnimationInProgress = false;
            this.transitionAnimationPreviewMode = false;
            this.transitionAnimationStartTime = 0L;
            runnable.run();
            this.onCloseAnimationEndRunnable = null;
            checkNeedRebuild();
        }
    }

    private void checkNeedRebuild() {
        if (this.rebuildAfterAnimation) {
            rebuildAllFragmentViews(this.rebuildLastAfterAnimation, this.showLastAfterAnimation);
            this.rebuildAfterAnimation = false;
        } else if (this.animateThemeAfterAnimation) {
            animateThemedValues(this.animateSetThemeAfterAnimation, this.animateSetThemeNightAfterAnimation);
            this.animateSetThemeAfterAnimation = null;
            this.animateThemeAfterAnimation = false;
        }
    }

    private void onOpenAnimationEnd() {
        Runnable runnable;
        if (this.transitionAnimationInProgress && (runnable = this.onOpenAnimationEndRunnable) != null) {
            this.transitionAnimationInProgress = false;
            this.transitionAnimationPreviewMode = false;
            this.transitionAnimationStartTime = 0L;
            runnable.run();
            this.onOpenAnimationEndRunnable = null;
            checkNeedRebuild();
        }
    }

    public void startActivityForResult(Intent intent, int requestCode) {
        FragmentActivity fragmentActivity = this.parentActivity;
        if (fragmentActivity == null) {
            return;
        }
        if (this.transitionAnimationInProgress) {
            AnimatorSet animatorSet = this.currentAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.currentAnimation = null;
            }
            if (this.onCloseAnimationEndRunnable != null) {
                onCloseAnimationEnd();
            } else if (this.onOpenAnimationEndRunnable != null) {
                onOpenAnimationEnd();
            }
            this.containerView.invalidate();
            if (intent != null) {
                this.parentActivity.startActivityForResult(intent, requestCode);
                return;
            }
            return;
        }
        if (intent != null) {
            fragmentActivity.startActivityForResult(intent, requestCode);
        }
    }

    public void setUseAlphaAnimations(boolean value) {
        this.useAlphaAnimations = value;
    }

    public void setBackgroundView(View view) {
        this.backgroundView = view;
    }

    public void setDrawerLayoutContainer(DrawerLayoutContainer layout) {
        this.drawerLayoutContainer = layout;
    }

    public DrawerLayoutContainer getDrawerLayoutContainer() {
        return this.drawerLayoutContainer;
    }

    public void setRemoveActionBarExtraHeight(boolean value) {
        this.removeActionBarExtraHeight = value;
    }

    public void setTitleOverlayText(String title, int titleId, Runnable action) {
        this.titleOverlayText = title;
        this.titleOverlayTextId = titleId;
        this.overlayAction = action;
        for (int a = 0; a < this.fragmentsStack.size(); a++) {
            BaseFragment fragment = this.fragmentsStack.get(a);
            if (fragment instanceof IndexActivity) {
                ((IndexActivity) fragment).updateTite(this.titleOverlayText, this.titleOverlayTextId, action);
            }
            if (fragment.actionBar != null) {
                fragment.actionBar.setTitleOverlayText(this.titleOverlayText, this.titleOverlayTextId, action);
            }
        }
    }

    public boolean extendActionMode(Menu menu) {
        if (!this.fragmentsStack.isEmpty()) {
            ArrayList<BaseFragment> arrayList = this.fragmentsStack;
            if (arrayList.get(arrayList.size() - 1).extendActionMode(menu)) {
                return true;
            }
        }
        return false;
    }

    @Override // android.view.View
    public boolean hasOverlappingRendering() {
        return false;
    }

    public BaseFragment getCurrentFragment() {
        return this.fragmentsStack.get(r0.size() - 1);
    }

    public void moveTaskToBack(boolean animated) {
        BaseFragment previousFragment;
        View fragmentView;
        ActionBarLayoutDelegate actionBarLayoutDelegate = this.delegate;
        if ((actionBarLayoutDelegate != null && !actionBarLayoutDelegate.needCloseLastFragment(this)) || checkTransitionAnimation() || this.fragmentsStack.isEmpty()) {
            return;
        }
        if (this.parentActivity.getCurrentFocus() != null) {
            AndroidUtilities.hideKeyboard(this.parentActivity.getCurrentFocus());
        }
        setInnerTranslationX(0.0f);
        boolean needAnimation = this.inPreviewMode || this.transitionAnimationPreviewMode || (animated && MessagesController.getGlobalMainSettings().getBoolean("view_animations", true));
        ArrayList<BaseFragment> arrayList = this.fragmentsStack;
        final BaseFragment currentFragment = arrayList.get(arrayList.size() - 1);
        this.fragmentsBackGround.add(currentFragment);
        if (this.fragmentsStack.size() <= 1) {
            previousFragment = null;
        } else {
            ArrayList<BaseFragment> arrayList2 = this.fragmentsStack;
            BaseFragment previousFragment2 = arrayList2.get(arrayList2.size() - 2);
            previousFragment = previousFragment2;
        }
        if (previousFragment != null) {
            LinearLayoutContainer temp = this.containerView;
            this.containerView = this.containerViewBack;
            this.containerViewBack = temp;
            previousFragment.setParentLayout(this);
            View fragmentView2 = previousFragment.fragmentView;
            if (fragmentView2 != null) {
                fragmentView = fragmentView2;
            } else {
                fragmentView = previousFragment.createView(this.parentActivity);
            }
            if (!this.inPreviewMode) {
                this.containerView.setVisibility(0);
                if (previousFragment.actionBar != null && previousFragment.actionBar.getAddToContainer()) {
                    if (this.removeActionBarExtraHeight) {
                        previousFragment.actionBar.setOccupyStatusBar(false);
                    }
                    ViewGroup parent = (ViewGroup) previousFragment.actionBar.getParent();
                    if (parent != null) {
                        parent.removeView(previousFragment.actionBar);
                    }
                    this.containerView.addView(previousFragment.actionBar);
                    previousFragment.actionBar.setTitleOverlayText(this.titleOverlayText, this.titleOverlayTextId, this.overlayAction);
                }
                ViewGroup parent2 = (ViewGroup) fragmentView.getParent();
                if (parent2 != null) {
                    previousFragment.onRemoveFromParent();
                    try {
                        parent2.removeView(fragmentView);
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                }
                this.containerView.addView(fragmentView);
                LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) fragmentView.getLayoutParams();
                layoutParams.width = -1;
                layoutParams.height = -1;
                layoutParams.leftMargin = 0;
                layoutParams.rightMargin = 0;
                layoutParams.bottomMargin = 0;
                layoutParams.topMargin = 0;
                fragmentView.setLayoutParams(layoutParams);
            }
            previousFragment.onTransitionAnimationStart(true, true);
            currentFragment.onTransitionAnimationStart(false, true);
            previousFragment.onResume();
            if (this.themeAnimatorSet != null) {
                this.presentingFragmentDescriptions = previousFragment.getThemeDescriptions();
            }
            this.currentActionBar = previousFragment.actionBar;
            if (!previousFragment.hasOwnBackground && fragmentView.getBackground() == null) {
                fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            if (!needAnimation) {
                if (currentFragment.fragmentView.getParent() != null) {
                    ((ViewGroup) currentFragment.fragmentView.getParent()).removeView(currentFragment.fragmentView);
                }
                this.fragmentsStack.remove(currentFragment);
                this.containerViewBack.setVisibility(8);
                bringChildToFront(this.containerView);
            }
            if (needAnimation) {
                this.transitionAnimationStartTime = System.currentTimeMillis();
                this.transitionAnimationInProgress = true;
                final BaseFragment previousFragmentFinal = previousFragment;
                this.onCloseAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$8iGMYN7CvijXf_Na4mGpN1DVTAQ
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$moveTaskToBack$12$ActionBarLayout(currentFragment, previousFragmentFinal);
                    }
                };
                AnimatorSet animation = null;
                if (!this.inPreviewMode && !this.transitionAnimationPreviewMode) {
                    animation = currentFragment.onCustomTransitionAnimation(false, new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$iuNz1e4fGtMArG93NjKcWcx-OyA
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$moveTaskToBack$13$ActionBarLayout();
                        }
                    });
                }
                if (animation == null) {
                    if (this.containerView.isKeyboardVisible || this.containerViewBack.isKeyboardVisible) {
                        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.17
                            @Override // java.lang.Runnable
                            public void run() {
                                if (ActionBarLayout.this.waitingForKeyboardCloseRunnable == this) {
                                    ActionBarLayout.this.waitingForKeyboardCloseRunnable = null;
                                    ActionBarLayout.this.startLayoutAnimation(false, true, false);
                                }
                            }
                        };
                        this.waitingForKeyboardCloseRunnable = runnable;
                        AndroidUtilities.runOnUIThread(runnable, 200L);
                        return;
                    }
                    startLayoutAnimation(false, true, this.inPreviewMode || this.transitionAnimationPreviewMode);
                    return;
                }
                this.currentAnimation = animation;
                return;
            }
            currentFragment.onTransitionAnimationEnd(false, true);
            previousFragment.onTransitionAnimationEnd(true, true);
            previousFragment.onBecomeFullyVisible();
            return;
        }
        if (this.useAlphaAnimations) {
            this.transitionAnimationStartTime = System.currentTimeMillis();
            this.transitionAnimationInProgress = true;
            this.onCloseAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$ZMYb2bWGmDURlrLMwOnRpW1OXqM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$moveTaskToBack$14$ActionBarLayout(currentFragment);
                }
            };
            ArrayList<Animator> animators = new ArrayList<>();
            animators.add(ObjectAnimator.ofFloat(this, "alpha", 1.0f, 0.0f));
            View view = this.backgroundView;
            if (view != null) {
                animators.add(ObjectAnimator.ofFloat(view, "alpha", 1.0f, 0.0f));
            }
            AnimatorSet animatorSet = new AnimatorSet();
            this.currentAnimation = animatorSet;
            animatorSet.playTogether(animators);
            this.currentAnimation.setInterpolator(this.accelerateDecelerateInterpolator);
            this.currentAnimation.setDuration(200L);
            this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.18
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationStart(Animator animation2) {
                    ActionBarLayout.this.transitionAnimationStartTime = System.currentTimeMillis();
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation2) {
                    ActionBarLayout.this.onAnimationEndCheck(false);
                }
            });
            this.currentAnimation.start();
            return;
        }
        this.fragmentsStack.remove(currentFragment);
        setVisibility(8);
        View view2 = this.backgroundView;
        if (view2 != null) {
            view2.setVisibility(8);
        }
    }

    public /* synthetic */ void lambda$moveTaskToBack$12$ActionBarLayout(BaseFragment currentFragment, BaseFragment previousFragmentFinal) {
        if (this.inPreviewMode || this.transitionAnimationPreviewMode) {
            this.containerViewBack.setScaleX(1.0f);
            this.containerViewBack.setScaleY(1.0f);
            this.inPreviewMode = false;
            this.transitionAnimationPreviewMode = false;
        } else {
            this.containerViewBack.setTranslationX(0.0f);
        }
        if (currentFragment.fragmentView.getParent() != null) {
            ((ViewGroup) currentFragment.fragmentView.getParent()).removeView(currentFragment.fragmentView);
        }
        this.fragmentsStack.remove(currentFragment);
        this.containerViewBack.setVisibility(8);
        bringChildToFront(this.containerView);
        currentFragment.onTransitionAnimationEnd(false, true);
        previousFragmentFinal.onTransitionAnimationEnd(true, true);
        previousFragmentFinal.onBecomeFullyVisible();
    }

    public /* synthetic */ void lambda$moveTaskToBack$13$ActionBarLayout() {
        onAnimationEndCheck(false);
    }

    public /* synthetic */ void lambda$moveTaskToBack$14$ActionBarLayout(BaseFragment currentFragment) {
        this.fragmentsStack.remove(currentFragment);
        setVisibility(8);
        View view = this.backgroundView;
        if (view != null) {
            view.setVisibility(8);
        }
        DrawerLayoutContainer drawerLayoutContainer = this.drawerLayoutContainer;
        if (drawerLayoutContainer != null) {
            drawerLayoutContainer.setAllowOpenDrawer(false, false);
        }
    }

    public void restoreTaskFromBack(boolean needAnimation) {
        final BaseFragment currentFragment;
        if (!this.fragmentsBackGround.isEmpty()) {
            final BaseFragment fragment = this.fragmentsBackGround.get(0);
            if (this.fragmentsStack.isEmpty()) {
                currentFragment = null;
            } else {
                ArrayList<BaseFragment> arrayList = this.fragmentsStack;
                currentFragment = arrayList.get(arrayList.size() - 1);
            }
            fragment.setParentLayout(this);
            View fragmentView = fragment.fragmentView;
            if (fragmentView == null) {
                fragmentView = fragment.createView(this.parentActivity);
            } else {
                ViewGroup parent = (ViewGroup) fragmentView.getParent();
                if (parent != null) {
                    fragment.onRemoveFromParent();
                    parent.removeView(fragmentView);
                }
            }
            if (fragment.actionBar != null && fragment.actionBar.getAddToContainer()) {
                if (this.removeActionBarExtraHeight) {
                    fragment.actionBar.setOccupyStatusBar(false);
                }
                ViewGroup parent2 = (ViewGroup) fragment.actionBar.getParent();
                if (parent2 != null) {
                    parent2.removeView(fragment.actionBar);
                }
                this.containerViewBack.addView(fragment.actionBar);
                fragment.actionBar.setTitleOverlayText(this.titleOverlayText, this.titleOverlayTextId, this.overlayAction);
            }
            this.containerViewBack.addView(fragmentView);
            LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) fragmentView.getLayoutParams();
            layoutParams.width = -1;
            layoutParams.height = -1;
            layoutParams.leftMargin = 0;
            layoutParams.rightMargin = 0;
            layoutParams.bottomMargin = 0;
            layoutParams.topMargin = 0;
            fragmentView.setLayoutParams(layoutParams);
            this.fragmentsStack.add(fragment);
            fragment.onResume();
            this.currentActionBar = fragment.actionBar;
            if (!fragment.hasOwnBackground && fragmentView.getBackground() == null) {
                fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            LinearLayoutContainer temp = this.containerView;
            LinearLayoutContainer linearLayoutContainer = this.containerViewBack;
            this.containerView = linearLayoutContainer;
            this.containerViewBack = temp;
            linearLayoutContainer.setVisibility(0);
            setInnerTranslationX(0.0f);
            this.containerView.setTranslationY(0.0f);
            bringChildToFront(this.containerView);
            if (this.themeAnimatorSet != null) {
                this.presentingFragmentDescriptions = fragment.getThemeDescriptions();
            }
            if (needAnimation) {
                if (this.useAlphaAnimations && this.fragmentsStack.size() == 1) {
                    presentFragmentInternalRemoveOld(false, currentFragment);
                    this.transitionAnimationStartTime = System.currentTimeMillis();
                    this.transitionAnimationInProgress = true;
                    this.onOpenAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$3hizD05Ny_cp-dV3MFJiPAeA4kU
                        @Override // java.lang.Runnable
                        public final void run() {
                            ActionBarLayout.lambda$restoreTaskFromBack$15(currentFragment, fragment);
                        }
                    };
                    ArrayList<Animator> animators = new ArrayList<>();
                    animators.add(ObjectAnimator.ofFloat(this, "alpha", 0.0f, 1.0f));
                    View view = this.backgroundView;
                    if (view != null) {
                        view.setVisibility(0);
                        animators.add(ObjectAnimator.ofFloat(this.backgroundView, "alpha", 0.0f, 1.0f));
                    }
                    if (currentFragment != null) {
                        currentFragment.onTransitionAnimationStart(false, false);
                    }
                    fragment.onTransitionAnimationStart(true, false);
                    AnimatorSet animatorSet = new AnimatorSet();
                    this.currentAnimation = animatorSet;
                    animatorSet.playTogether(animators);
                    this.currentAnimation.setInterpolator(this.accelerateDecelerateInterpolator);
                    this.currentAnimation.setDuration(200L);
                    this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.19
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            ActionBarLayout.this.onAnimationEndCheck(false);
                        }
                    });
                    this.currentAnimation.start();
                } else {
                    this.transitionAnimationPreviewMode = false;
                    this.transitionAnimationStartTime = System.currentTimeMillis();
                    this.transitionAnimationInProgress = true;
                    this.onOpenAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$62amSXLyvBvUMYEsl2x29PqZpOM
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$restoreTaskFromBack$16$ActionBarLayout(currentFragment, fragment);
                        }
                    };
                    if (currentFragment != null) {
                        currentFragment.onTransitionAnimationStart(false, false);
                    }
                    fragment.onTransitionAnimationStart(true, false);
                    AnimatorSet animation = fragment.onCustomTransitionAnimation(true, new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarLayout$w0HeLFapzBYK3YDslLii-2BUuBs
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$restoreTaskFromBack$17$ActionBarLayout();
                        }
                    });
                    if (animation == null) {
                        this.containerView.setAlpha(0.0f);
                        this.containerView.setTranslationX(48.0f);
                        this.containerView.setScaleX(1.0f);
                        this.containerView.setScaleY(1.0f);
                        if (this.containerView.isKeyboardVisible || this.containerViewBack.isKeyboardVisible) {
                            Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.20
                                @Override // java.lang.Runnable
                                public void run() {
                                    if (ActionBarLayout.this.waitingForKeyboardCloseRunnable == this) {
                                        ActionBarLayout.this.waitingForKeyboardCloseRunnable = null;
                                        ActionBarLayout.this.startLayoutAnimation(true, true, false);
                                    }
                                }
                            };
                            this.waitingForKeyboardCloseRunnable = runnable;
                            AndroidUtilities.runOnUIThread(runnable, 200L);
                        } else if (fragment.needDelayOpenAnimation()) {
                            Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.21
                                @Override // java.lang.Runnable
                                public void run() {
                                    if (ActionBarLayout.this.delayedOpenAnimationRunnable == this) {
                                        ActionBarLayout.this.delayedOpenAnimationRunnable = null;
                                        ActionBarLayout.this.startLayoutAnimation(true, true, false);
                                    }
                                }
                            };
                            this.delayedOpenAnimationRunnable = runnable2;
                            AndroidUtilities.runOnUIThread(runnable2, 200L);
                        } else {
                            startLayoutAnimation(true, true, false);
                        }
                    } else {
                        this.containerView.setAlpha(1.0f);
                        this.containerView.setTranslationX(0.0f);
                        this.currentAnimation = animation;
                    }
                }
            } else {
                View view2 = this.backgroundView;
                if (view2 != null) {
                    view2.setAlpha(1.0f);
                    this.backgroundView.setVisibility(0);
                }
                if (currentFragment != null) {
                    currentFragment.onTransitionAnimationStart(false, false);
                    currentFragment.onTransitionAnimationEnd(false, false);
                }
                fragment.onTransitionAnimationStart(true, false);
                fragment.onTransitionAnimationEnd(true, false);
                fragment.onBecomeFullyVisible();
            }
        }
        this.fragmentsBackGround.clear();
    }

    static /* synthetic */ void lambda$restoreTaskFromBack$15(BaseFragment currentFragment, BaseFragment fragment) {
        if (currentFragment != null) {
            currentFragment.onTransitionAnimationEnd(false, false);
        }
        fragment.onTransitionAnimationEnd(true, false);
        fragment.onBecomeFullyVisible();
    }

    public /* synthetic */ void lambda$restoreTaskFromBack$16$ActionBarLayout(BaseFragment currentFragment, BaseFragment fragment) {
        presentFragmentInternalRemoveOld(false, currentFragment);
        this.containerView.setTranslationX(0.0f);
        if (currentFragment != null) {
            currentFragment.onTransitionAnimationEnd(false, false);
        }
        fragment.onTransitionAnimationEnd(true, false);
        fragment.onBecomeFullyVisible();
    }

    public /* synthetic */ void lambda$restoreTaskFromBack$17$ActionBarLayout() {
        onAnimationEndCheck(false);
    }
}
