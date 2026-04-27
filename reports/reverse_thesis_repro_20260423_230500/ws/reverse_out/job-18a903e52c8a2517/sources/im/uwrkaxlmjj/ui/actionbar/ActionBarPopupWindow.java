package im.uwrkaxlmjj.ui.actionbar;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.util.Property;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.ScrollView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ActionBarPopupWindow extends PopupWindow {
    private static final ViewTreeObserver.OnScrollChangedListener NOP;
    private static final boolean allowAnimation;
    private static DecelerateInterpolator decelerateInterpolator;
    private static Method layoutInScreenMethod;
    private static final Field superListenerField;
    private boolean animationEnabled;
    private int dismissAnimationDuration;
    private ViewTreeObserver.OnScrollChangedListener mSuperScrollListener;
    private ViewTreeObserver mViewTreeObserver;
    private AnimatorSet windowAnimatorSet;

    public interface OnDispatchKeyEventListener {
        void onDispatchKeyEvent(KeyEvent keyEvent);
    }

    static {
        allowAnimation = Build.VERSION.SDK_INT >= 18;
        decelerateInterpolator = new DecelerateInterpolator();
        Field f = null;
        try {
            f = PopupWindow.class.getDeclaredField("mOnScrollChangedListener");
            f.setAccessible(true);
        } catch (NoSuchFieldException e) {
        }
        superListenerField = f;
        NOP = new ViewTreeObserver.OnScrollChangedListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarPopupWindow$oZqIRnOkkJ4TLXS1vePtysDTkHw
            @Override // android.view.ViewTreeObserver.OnScrollChangedListener
            public final void onScrollChanged() {
                ActionBarPopupWindow.lambda$static$0();
            }
        };
    }

    static /* synthetic */ void lambda$static$0() {
    }

    public static class ActionBarPopupWindowLayout extends FrameLayout {
        private boolean animationEnabled;
        private int backAlpha;
        private float backScaleX;
        private float backScaleY;
        protected Drawable backgroundDrawable;
        private ArrayList<AnimatorSet> itemAnimators;
        private int lastStartedChild;
        protected LinearLayout linearLayout;
        private OnDispatchKeyEventListener mOnDispatchKeyEventListener;
        private HashMap<View, Integer> positions;
        private ScrollView scrollView;
        private boolean showedFromBotton;

        public ActionBarPopupWindowLayout(Context context) {
            super(context);
            this.backScaleX = 1.0f;
            this.backScaleY = 1.0f;
            this.backAlpha = 255;
            this.lastStartedChild = 0;
            this.animationEnabled = ActionBarPopupWindow.allowAnimation;
            this.positions = new HashMap<>();
            Drawable drawableMutate = getResources().getDrawable(R.drawable.popup_fixed_alert3).mutate();
            this.backgroundDrawable = drawableMutate;
            drawableMutate.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_actionBarDefaultSubmenuBackground), PorterDuff.Mode.MULTIPLY));
            setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f));
            setWillNotDraw(false);
            try {
                ScrollView scrollView = new ScrollView(context);
                this.scrollView = scrollView;
                scrollView.setVerticalScrollBarEnabled(false);
                addView(this.scrollView, LayoutHelper.createFrame(-2, -2.0f));
            } catch (Throwable e) {
                FileLog.e(e);
            }
            LinearLayout linearLayout = new LinearLayout(context);
            this.linearLayout = linearLayout;
            linearLayout.setOrientation(1);
            ScrollView scrollView2 = this.scrollView;
            if (scrollView2 == null) {
                addView(this.linearLayout, LayoutHelper.createFrame(-2, -2.0f));
            } else {
                scrollView2.addView(this.linearLayout, new FrameLayout.LayoutParams(-2, -2));
            }
        }

        public void setShowedFromBotton(boolean value) {
            this.showedFromBotton = value;
        }

        public void setDispatchKeyEventListener(OnDispatchKeyEventListener listener) {
            this.mOnDispatchKeyEventListener = listener;
        }

        public void setBackAlpha(int value) {
            this.backAlpha = value;
        }

        public int getBackAlpha() {
            return this.backAlpha;
        }

        public void setBackScaleX(float value) {
            this.backScaleX = value;
            invalidate();
        }

        public void setBackScaleY(float value) {
            this.backScaleY = value;
            if (this.animationEnabled) {
                int height = getMeasuredHeight() - AndroidUtilities.dp(16.0f);
                if (this.showedFromBotton) {
                    for (int a = this.lastStartedChild; a >= 0; a--) {
                        View child = getItemAt(a);
                        if (child.getVisibility() == 0) {
                            Integer position = this.positions.get(child);
                            if (position != null && height - ((position.intValue() * AndroidUtilities.dp(48.0f)) + AndroidUtilities.dp(32.0f)) > height * value) {
                                break;
                            }
                            this.lastStartedChild = a - 1;
                            startChildAnimation(child);
                        }
                    }
                } else {
                    int count = getItemsCount();
                    for (int a2 = this.lastStartedChild; a2 < count; a2++) {
                        View child2 = getItemAt(a2);
                        if (child2.getVisibility() == 0) {
                            Integer position2 = this.positions.get(child2);
                            if (position2 != null && ((position2.intValue() + 1) * AndroidUtilities.dp(48.0f)) - AndroidUtilities.dp(24.0f) > height * value) {
                                break;
                            }
                            this.lastStartedChild = a2 + 1;
                            startChildAnimation(child2);
                        }
                    }
                }
            }
            invalidate();
        }

        @Override // android.view.View
        public void setBackgroundDrawable(Drawable drawable) {
            this.backgroundDrawable = drawable;
        }

        private void startChildAnimation(View child) {
            if (this.animationEnabled) {
                final AnimatorSet animatorSet = new AnimatorSet();
                Animator[] animatorArr = new Animator[2];
                animatorArr[0] = ObjectAnimator.ofFloat(child, (Property<View, Float>) View.ALPHA, 0.0f, 1.0f);
                Property property = View.TRANSLATION_Y;
                float[] fArr = new float[2];
                fArr[0] = AndroidUtilities.dp(this.showedFromBotton ? 6.0f : -6.0f);
                fArr[1] = 0.0f;
                animatorArr[1] = ObjectAnimator.ofFloat(child, (Property<View, Float>) property, fArr);
                animatorSet.playTogether(animatorArr);
                animatorSet.setDuration(180L);
                animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow.ActionBarPopupWindowLayout.1
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        ActionBarPopupWindowLayout.this.itemAnimators.remove(animatorSet);
                    }
                });
                animatorSet.setInterpolator(ActionBarPopupWindow.decelerateInterpolator);
                animatorSet.start();
                if (this.itemAnimators == null) {
                    this.itemAnimators = new ArrayList<>();
                }
                this.itemAnimators.add(animatorSet);
            }
        }

        public void setAnimationEnabled(boolean value) {
            this.animationEnabled = value;
        }

        @Override // android.view.ViewGroup
        public void addView(View child) {
            this.linearLayout.addView(child);
        }

        public void removeInnerViews() {
            this.linearLayout.removeAllViews();
        }

        public float getBackScaleX() {
            return this.backScaleX;
        }

        public float getBackScaleY() {
            return this.backScaleY;
        }

        @Override // android.view.ViewGroup, android.view.View
        public boolean dispatchKeyEvent(KeyEvent event) {
            OnDispatchKeyEventListener onDispatchKeyEventListener = this.mOnDispatchKeyEventListener;
            if (onDispatchKeyEventListener != null) {
                onDispatchKeyEventListener.onDispatchKeyEvent(event);
            }
            return super.dispatchKeyEvent(event);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            Drawable drawable = this.backgroundDrawable;
            if (drawable != null) {
                drawable.setAlpha(this.backAlpha);
                getMeasuredHeight();
                if (this.showedFromBotton) {
                    this.backgroundDrawable.setBounds(0, (int) (getMeasuredHeight() * (1.0f - this.backScaleY)), (int) (getMeasuredWidth() * this.backScaleX), getMeasuredHeight());
                } else {
                    this.backgroundDrawable.setBounds(0, 0, (int) (getMeasuredWidth() * this.backScaleX), (int) (getMeasuredHeight() * this.backScaleY));
                }
                this.backgroundDrawable.draw(canvas);
            }
        }

        public Drawable getBackgroundDrawable() {
            return this.backgroundDrawable;
        }

        public int getItemsCount() {
            return this.linearLayout.getChildCount();
        }

        public View getItemAt(int index) {
            return this.linearLayout.getChildAt(index);
        }

        public void scrollToTop() {
            ScrollView scrollView = this.scrollView;
            if (scrollView != null) {
                scrollView.scrollTo(0, 0);
            }
        }
    }

    public ActionBarPopupWindow() {
        this.animationEnabled = allowAnimation;
        this.dismissAnimationDuration = 150;
        init();
    }

    public ActionBarPopupWindow(Context context) {
        super(context);
        this.animationEnabled = allowAnimation;
        this.dismissAnimationDuration = 150;
        init();
    }

    public ActionBarPopupWindow(int width, int height) {
        super(width, height);
        this.animationEnabled = allowAnimation;
        this.dismissAnimationDuration = 150;
        init();
    }

    public ActionBarPopupWindow(View contentView) {
        super(contentView);
        this.animationEnabled = allowAnimation;
        this.dismissAnimationDuration = 150;
        init();
    }

    public ActionBarPopupWindow(View contentView, int width, int height, boolean focusable) {
        super(contentView, width, height, focusable);
        this.animationEnabled = allowAnimation;
        this.dismissAnimationDuration = 150;
        init();
    }

    public ActionBarPopupWindow(View contentView, int width, int height) {
        super(contentView, width, height);
        this.animationEnabled = allowAnimation;
        this.dismissAnimationDuration = 150;
        init();
    }

    public void setAnimationEnabled(boolean value) {
        this.animationEnabled = value;
    }

    public void setLayoutInScreen(boolean value) {
        try {
            if (layoutInScreenMethod == null) {
                Method declaredMethod = PopupWindow.class.getDeclaredMethod("setLayoutInScreenEnabled", Boolean.TYPE);
                layoutInScreenMethod = declaredMethod;
                declaredMethod.setAccessible(true);
            }
            layoutInScreenMethod.invoke(this, true);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void init() {
        Field field = superListenerField;
        if (field != null) {
            try {
                this.mSuperScrollListener = (ViewTreeObserver.OnScrollChangedListener) field.get(this);
                superListenerField.set(this, NOP);
            } catch (Exception e) {
                this.mSuperScrollListener = null;
            }
        }
    }

    public void setDismissAnimationDuration(int value) {
        this.dismissAnimationDuration = value;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void unregisterListener() {
        ViewTreeObserver viewTreeObserver;
        if (this.mSuperScrollListener != null && (viewTreeObserver = this.mViewTreeObserver) != null) {
            if (viewTreeObserver.isAlive()) {
                this.mViewTreeObserver.removeOnScrollChangedListener(this.mSuperScrollListener);
            }
            this.mViewTreeObserver = null;
        }
    }

    private void registerListener(View anchor) {
        if (this.mSuperScrollListener != null) {
            ViewTreeObserver vto = anchor.getWindowToken() != null ? anchor.getViewTreeObserver() : null;
            ViewTreeObserver viewTreeObserver = this.mViewTreeObserver;
            if (vto != viewTreeObserver) {
                if (viewTreeObserver != null && viewTreeObserver.isAlive()) {
                    this.mViewTreeObserver.removeOnScrollChangedListener(this.mSuperScrollListener);
                }
                this.mViewTreeObserver = vto;
                if (vto != null) {
                    vto.addOnScrollChangedListener(this.mSuperScrollListener);
                }
            }
        }
    }

    public void dimBehind() {
        View container = getContentView().getRootView();
        Context context = getContentView().getContext();
        WindowManager wm = (WindowManager) context.getSystemService("window");
        WindowManager.LayoutParams p = (WindowManager.LayoutParams) container.getLayoutParams();
        p.flags |= 2;
        p.dimAmount = 0.2f;
        wm.updateViewLayout(container, p);
    }

    @Override // android.widget.PopupWindow
    public void showAsDropDown(View anchor, int xoff, int yoff) {
        try {
            super.showAsDropDown(anchor, xoff - AndroidUtilities.dp(4.5f), yoff);
            registerListener(anchor);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void startAnimation() {
        if (!this.animationEnabled || this.windowAnimatorSet != null) {
            return;
        }
        ActionBarPopupWindowLayout content = (ActionBarPopupWindowLayout) getContentView();
        content.setTranslationY(0.0f);
        content.setAlpha(1.0f);
        content.setPivotX(content.getMeasuredWidth());
        content.setPivotY(0.0f);
        int count = content.getItemsCount();
        content.positions.clear();
        int visibleCount = 0;
        for (int a = 0; a < count; a++) {
            View child = content.getItemAt(a);
            child.setAlpha(0.0f);
            if (child.getVisibility() == 0) {
                content.positions.put(child, Integer.valueOf(visibleCount));
                visibleCount++;
            }
        }
        if (content.showedFromBotton) {
            content.lastStartedChild = count - 1;
        } else {
            content.lastStartedChild = 0;
        }
        if (visibleCount > 1) {
            content.setPadding(0, AndroidUtilities.dp(23.5f), 0, AndroidUtilities.dp(15.0f));
        } else {
            content.setPadding(0, AndroidUtilities.dp(8.5f), 0, 0);
        }
        AnimatorSet animatorSet = new AnimatorSet();
        this.windowAnimatorSet = animatorSet;
        animatorSet.playTogether(ObjectAnimator.ofFloat(content, "backScaleY", 0.0f, 1.0f), ObjectAnimator.ofInt(content, "backAlpha", 0, 255));
        this.windowAnimatorSet.setDuration((visibleCount * 16) + 150);
        this.windowAnimatorSet.addListener(new Animator.AnimatorListener() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow.1
            @Override // android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animation) {
            }

            @Override // android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                ActionBarPopupWindow.this.windowAnimatorSet = null;
                ActionBarPopupWindowLayout content2 = (ActionBarPopupWindowLayout) ActionBarPopupWindow.this.getContentView();
                int count2 = content2.getItemsCount();
                for (int a2 = 0; a2 < count2; a2++) {
                    View child2 = content2.getItemAt(a2);
                    child2.setAlpha(1.0f);
                }
            }

            @Override // android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                onAnimationEnd(animation);
            }

            @Override // android.animation.Animator.AnimatorListener
            public void onAnimationRepeat(Animator animation) {
            }
        });
        this.windowAnimatorSet.start();
    }

    @Override // android.widget.PopupWindow
    public void update(View anchor, int xoff, int yoff, int width, int height) {
        super.update(anchor, xoff, yoff, width, height);
        registerListener(anchor);
    }

    @Override // android.widget.PopupWindow
    public void update(View anchor, int width, int height) {
        super.update(anchor, width, height);
        registerListener(anchor);
    }

    @Override // android.widget.PopupWindow
    public void showAtLocation(View parent, int gravity, int x, int y) {
        super.showAtLocation(parent, gravity, x, y);
        unregisterListener();
    }

    @Override // android.widget.PopupWindow
    public void dismiss() {
        dismiss(true);
    }

    public void dismiss(boolean animated) {
        setFocusable(false);
        if (this.animationEnabled && animated) {
            AnimatorSet animatorSet = this.windowAnimatorSet;
            if (animatorSet != null) {
                animatorSet.cancel();
            }
            ActionBarPopupWindowLayout content = (ActionBarPopupWindowLayout) getContentView();
            if (content.itemAnimators != null && content.itemAnimators.isEmpty()) {
                int N = content.itemAnimators.size();
                for (int a = 0; a < N; a++) {
                    ((AnimatorSet) content.itemAnimators.get(a)).cancel();
                }
                content.itemAnimators.clear();
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.windowAnimatorSet = animatorSet2;
            Animator[] animatorArr = new Animator[2];
            Property property = View.TRANSLATION_Y;
            float[] fArr = new float[1];
            fArr[0] = AndroidUtilities.dp(content.showedFromBotton ? 5.0f : -5.0f);
            animatorArr[0] = ObjectAnimator.ofFloat(content, (Property<ActionBarPopupWindowLayout, Float>) property, fArr);
            animatorArr[1] = ObjectAnimator.ofFloat(content, (Property<ActionBarPopupWindowLayout, Float>) View.ALPHA, 0.0f);
            animatorSet2.playTogether(animatorArr);
            this.windowAnimatorSet.setDuration(this.dismissAnimationDuration);
            this.windowAnimatorSet.addListener(new Animator.AnimatorListener() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow.2
                @Override // android.animation.Animator.AnimatorListener
                public void onAnimationStart(Animator animation) {
                }

                @Override // android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    ActionBarPopupWindow.this.windowAnimatorSet = null;
                    ActionBarPopupWindow.this.setFocusable(false);
                    try {
                        ActionBarPopupWindow.super.dismiss();
                    } catch (Exception e) {
                    }
                    ActionBarPopupWindow.this.unregisterListener();
                }

                @Override // android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    onAnimationEnd(animation);
                }

                @Override // android.animation.Animator.AnimatorListener
                public void onAnimationRepeat(Animator animation) {
                }
            });
            this.windowAnimatorSet.start();
            return;
        }
        try {
            super.dismiss();
        } catch (Exception e) {
        }
        unregisterListener();
    }
}
