package im.uwrkaxlmjj.ui.hviews.pop;

import android.app.Activity;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.transition.Transition;
import android.util.Log;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewGroupOverlay;
import android.view.ViewTreeObserver;
import android.widget.PopupWindow;
import androidx.core.widget.PopupWindowCompat;
import im.uwrkaxlmjj.messenger.utils.BlurKit;
import im.uwrkaxlmjj.ui.hviews.pop.BasePopup;

/* JADX INFO: loaded from: classes5.dex */
public abstract class BasePopup<T extends BasePopup> implements PopupWindow.OnDismissListener {
    private static final float DEFAULT_DIM = 0.7f;
    private static final String TAG = "EasyPopup";
    private boolean isBackgroundDim;
    private boolean isBlurBackground;
    private View mAnchorView;
    private int mAnimationStyle;
    private View mContentView;
    private Context mContext;
    private ViewGroup mDimView;
    private Transition mEnterTransition;
    private Transition mExitTransition;
    private int mLayoutId;
    private int mOffsetX;
    private int mOffsetY;
    private PopupWindow.OnDismissListener mOnDismissListener;
    private OnRealWHAlreadyListener mOnRealWHAlreadyListener;
    private PopupWindow mPopupWindow;
    private boolean mFocusable = true;
    private boolean mOutsideTouchable = true;
    private int mWidth = -2;
    private int mHeight = -2;
    private float mDimValue = DEFAULT_DIM;
    private int mDimColor = -16777216;
    private boolean mFocusAndOutsideEnable = true;
    private int mYGravity = 2;
    private int mXGravity = 1;
    private int mInputMethodMode = 0;
    private int mSoftInputMode = 1;
    private boolean isNeedReMeasureWH = false;
    private boolean isRealWHAlready = false;
    private boolean isAtAnchorViewMethod = false;

    public interface OnRealWHAlreadyListener {
        void onRealWHAlready(BasePopup basePopup, int i, int i2, int i3, int i4);
    }

    protected abstract void initAttributes();

    protected abstract void initViews(View view, T t);

    protected T self() {
        return this;
    }

    public T apply() {
        if (this.mPopupWindow == null) {
            this.mPopupWindow = new PopupWindow();
        }
        onPopupWindowCreated();
        initContentViewAndWH();
        onPopupWindowViewCreated(this.mContentView);
        int i = this.mAnimationStyle;
        if (i != 0) {
            this.mPopupWindow.setAnimationStyle(i);
        }
        initFocusAndBack();
        this.mPopupWindow.setOnDismissListener(this);
        if (Build.VERSION.SDK_INT >= 23) {
            Transition transition = this.mEnterTransition;
            if (transition != null) {
                this.mPopupWindow.setEnterTransition(transition);
            }
            Transition transition2 = this.mExitTransition;
            if (transition2 != null) {
                this.mPopupWindow.setExitTransition(transition2);
            }
        }
        if (this.isBlurBackground) {
            BlurKit.init(this.mContext);
        }
        return (T) self();
    }

    private void initContentViewAndWH() {
        Context context;
        if (this.mContentView == null) {
            if (this.mLayoutId != 0 && (context = this.mContext) != null) {
                this.mContentView = LayoutInflater.from(context).inflate(this.mLayoutId, (ViewGroup) null);
            } else {
                throw new IllegalArgumentException("The content view is null,the layoutId=" + this.mLayoutId + ",context=" + this.mContext);
            }
        }
        this.mPopupWindow.setContentView(this.mContentView);
        int i = this.mWidth;
        if (i > 0 || i == -2 || i == -1) {
            this.mPopupWindow.setWidth(this.mWidth);
        } else {
            this.mPopupWindow.setWidth(-2);
        }
        int i2 = this.mHeight;
        if (i2 > 0 || i2 == -2 || i2 == -1) {
            this.mPopupWindow.setHeight(this.mHeight);
        } else {
            this.mPopupWindow.setHeight(-2);
        }
        measureContentView();
        registerOnGlobalLayoutListener();
        this.mPopupWindow.setInputMethodMode(this.mInputMethodMode);
        this.mPopupWindow.setSoftInputMode(this.mSoftInputMode);
    }

    private void initFocusAndBack() {
        if (!this.mFocusAndOutsideEnable) {
            this.mPopupWindow.setFocusable(true);
            this.mPopupWindow.setOutsideTouchable(false);
            this.mPopupWindow.setBackgroundDrawable(null);
            this.mPopupWindow.getContentView().setFocusable(true);
            this.mPopupWindow.getContentView().setFocusableInTouchMode(true);
            this.mPopupWindow.getContentView().setOnKeyListener(new View.OnKeyListener() { // from class: im.uwrkaxlmjj.ui.hviews.pop.BasePopup.1
                @Override // android.view.View.OnKeyListener
                public boolean onKey(View v, int keyCode, KeyEvent event) {
                    if (keyCode == 4) {
                        BasePopup.this.mPopupWindow.dismiss();
                        return true;
                    }
                    return false;
                }
            });
            this.mPopupWindow.setTouchInterceptor(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hviews.pop.BasePopup.2
                @Override // android.view.View.OnTouchListener
                public boolean onTouch(View v, MotionEvent event) {
                    int x = (int) event.getX();
                    int y = (int) event.getY();
                    if (event.getAction() == 0 && (x < 0 || x >= BasePopup.this.mWidth || y < 0 || y >= BasePopup.this.mHeight)) {
                        Log.d(BasePopup.TAG, "onTouch outside:mWidth=" + BasePopup.this.mWidth + ",mHeight=" + BasePopup.this.mHeight);
                        return true;
                    }
                    if (event.getAction() == 4) {
                        Log.d(BasePopup.TAG, "onTouch outside event:mWidth=" + BasePopup.this.mWidth + ",mHeight=" + BasePopup.this.mHeight);
                        return true;
                    }
                    return false;
                }
            });
            return;
        }
        this.mPopupWindow.setFocusable(this.mFocusable);
        this.mPopupWindow.setOutsideTouchable(this.mOutsideTouchable);
        this.mPopupWindow.setBackgroundDrawable(new ColorDrawable(0));
    }

    protected void onPopupWindowCreated() {
        initAttributes();
    }

    protected void onPopupWindowViewCreated(View contentView) {
        initViews(contentView, self());
    }

    protected void onPopupWindowDismiss() {
    }

    private void measureContentView() {
        View contentView = getContentView();
        if (this.mWidth <= 0 || this.mHeight <= 0) {
            contentView.measure(0, 0);
            if (this.mWidth <= 0) {
                this.mWidth = contentView.getMeasuredWidth();
            }
            if (this.mHeight <= 0) {
                this.mHeight = contentView.getMeasuredHeight();
            }
        }
    }

    private void registerOnGlobalLayoutListener() {
        getContentView().getViewTreeObserver().addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener() { // from class: im.uwrkaxlmjj.ui.hviews.pop.BasePopup.3
            @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
            public void onGlobalLayout() {
                BasePopup.this.getContentView().getViewTreeObserver().removeOnGlobalLayoutListener(this);
                BasePopup basePopup = BasePopup.this;
                basePopup.mWidth = basePopup.getContentView().getWidth();
                BasePopup basePopup2 = BasePopup.this;
                basePopup2.mHeight = basePopup2.getContentView().getHeight();
                BasePopup.this.isRealWHAlready = true;
                BasePopup.this.isNeedReMeasureWH = false;
                if (BasePopup.this.mOnRealWHAlreadyListener != null) {
                    OnRealWHAlreadyListener onRealWHAlreadyListener = BasePopup.this.mOnRealWHAlreadyListener;
                    BasePopup basePopup3 = BasePopup.this;
                    onRealWHAlreadyListener.onRealWHAlready(basePopup3, basePopup3.mWidth, BasePopup.this.mHeight, BasePopup.this.mAnchorView == null ? 0 : BasePopup.this.mAnchorView.getWidth(), BasePopup.this.mAnchorView == null ? 0 : BasePopup.this.mAnchorView.getHeight());
                }
                if (BasePopup.this.isShowing() && BasePopup.this.isAtAnchorViewMethod) {
                    BasePopup basePopup4 = BasePopup.this;
                    basePopup4.updateLocation(basePopup4.mWidth, BasePopup.this.mHeight, BasePopup.this.mAnchorView, BasePopup.this.mYGravity, BasePopup.this.mXGravity, BasePopup.this.mOffsetX, BasePopup.this.mOffsetY);
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateLocation(int width, int height, View anchor, int yGravity, int xGravity, int x, int y) {
        if (this.mPopupWindow == null) {
            return;
        }
        this.mPopupWindow.update(anchor, calculateX(anchor, xGravity, width, x), calculateY(anchor, yGravity, height, y), width, height);
    }

    public T setContext(Context context) {
        this.mContext = context;
        return (T) self();
    }

    public T setContentView(View view) {
        this.mContentView = view;
        this.mLayoutId = 0;
        return (T) self();
    }

    public T setContentView(int i) {
        this.mContentView = null;
        this.mLayoutId = i;
        return (T) self();
    }

    public T setContentView(Context context, int i) {
        this.mContext = context;
        this.mContentView = null;
        this.mLayoutId = i;
        return (T) self();
    }

    public T setContentView(View view, int i, int i2) {
        this.mContentView = view;
        this.mLayoutId = 0;
        this.mWidth = i;
        this.mHeight = i2;
        return (T) self();
    }

    public T setContentView(int i, int i2, int i3) {
        this.mContentView = null;
        this.mLayoutId = i;
        this.mWidth = i2;
        this.mHeight = i3;
        return (T) self();
    }

    public T setContentView(Context context, int i, int i2, int i3) {
        this.mContext = context;
        this.mContentView = null;
        this.mLayoutId = i;
        this.mWidth = i2;
        this.mHeight = i3;
        return (T) self();
    }

    public T setWidth(int i) {
        this.mWidth = i;
        return (T) self();
    }

    public T setHeight(int i) {
        this.mHeight = i;
        return (T) self();
    }

    public T setAnchorView(View view) {
        this.mAnchorView = view;
        return (T) self();
    }

    public T setYGravity(int i) {
        this.mYGravity = i;
        return (T) self();
    }

    public T setXGravity(int i) {
        this.mXGravity = i;
        return (T) self();
    }

    public T setOffsetX(int i) {
        this.mOffsetX = i;
        return (T) self();
    }

    public T setOffsetY(int i) {
        this.mOffsetY = i;
        return (T) self();
    }

    public T setAnimationStyle(int i) {
        this.mAnimationStyle = i;
        return (T) self();
    }

    public T setFocusable(boolean z) {
        this.mFocusable = z;
        return (T) self();
    }

    public T setOutsideTouchable(boolean z) {
        this.mOutsideTouchable = z;
        return (T) self();
    }

    public T setFocusAndOutsideEnable(boolean z) {
        this.mFocusAndOutsideEnable = z;
        return (T) self();
    }

    public T setBlurBackground(boolean z) {
        this.isBlurBackground = z;
        return (T) self();
    }

    public T setBackgroundDimEnable(boolean z) {
        this.isBackgroundDim = z;
        return (T) self();
    }

    public T setDimValue(float f) {
        this.mDimValue = f;
        return (T) self();
    }

    public T setDimColor(int i) {
        this.mDimColor = i;
        return (T) self();
    }

    public T setDimView(ViewGroup viewGroup) {
        this.mDimView = viewGroup;
        return (T) self();
    }

    public T setEnterTransition(Transition transition) {
        this.mEnterTransition = transition;
        return (T) self();
    }

    public T setExitTransition(Transition transition) {
        this.mExitTransition = transition;
        return (T) self();
    }

    public T setInputMethodMode(int i) {
        this.mInputMethodMode = i;
        return (T) self();
    }

    public T setSoftInputMode(int i) {
        this.mSoftInputMode = i;
        return (T) self();
    }

    public T setNeedReMeasureWH(boolean z) {
        this.isNeedReMeasureWH = z;
        return (T) self();
    }

    private void checkIsApply(boolean isAtAnchorView) {
        if (this.isAtAnchorViewMethod != isAtAnchorView) {
            this.isAtAnchorViewMethod = isAtAnchorView;
        }
        if (this.mPopupWindow == null) {
            apply();
        }
    }

    public void showAsDropDown() {
        View view = this.mAnchorView;
        if (view == null) {
            return;
        }
        showAsDropDown(view, this.mOffsetX, this.mOffsetY);
    }

    public void showAsDropDown(View anchor, int offsetX, int offsetY) {
        checkIsApply(false);
        handleBackgroundDim();
        this.mAnchorView = anchor;
        this.mOffsetX = offsetX;
        this.mOffsetY = offsetY;
        if (this.isNeedReMeasureWH) {
            registerOnGlobalLayoutListener();
        }
        this.mPopupWindow.showAsDropDown(anchor, this.mOffsetX, this.mOffsetY);
    }

    public void showAsDropDown(View anchor) {
        checkIsApply(false);
        handleBackgroundDim();
        this.mAnchorView = anchor;
        if (this.isNeedReMeasureWH) {
            registerOnGlobalLayoutListener();
        }
        this.mPopupWindow.showAsDropDown(anchor);
    }

    public void showAsDropDown(View anchor, int offsetX, int offsetY, int gravity) {
        checkIsApply(false);
        handleBackgroundDim();
        this.mAnchorView = anchor;
        this.mOffsetX = offsetX;
        this.mOffsetY = offsetY;
        if (this.isNeedReMeasureWH) {
            registerOnGlobalLayoutListener();
        }
        PopupWindowCompat.showAsDropDown(this.mPopupWindow, anchor, this.mOffsetX, this.mOffsetY, gravity);
    }

    public void showAtLocation(View parent, int gravity, int offsetX, int offsetY) {
        checkIsApply(false);
        handleBackgroundDim();
        this.mAnchorView = parent;
        this.mOffsetX = offsetX;
        this.mOffsetY = offsetY;
        if (this.isNeedReMeasureWH) {
            registerOnGlobalLayoutListener();
        }
        this.mPopupWindow.showAtLocation(parent, gravity, this.mOffsetX, this.mOffsetY);
    }

    public void showAtAnchorView() {
        View view = this.mAnchorView;
        if (view == null) {
            return;
        }
        showAtAnchorView(view, this.mYGravity, this.mXGravity);
    }

    public void showAtAnchorView(View anchor, int vertGravity, int horizGravity) {
        showAtAnchorView(anchor, vertGravity, horizGravity, 0, 0);
    }

    public void showAtAnchorView(View anchor, int vertGravity, int horizGravity, int x, int y) {
        checkIsApply(true);
        this.mAnchorView = anchor;
        this.mOffsetX = x;
        this.mOffsetY = y;
        this.mYGravity = vertGravity;
        this.mXGravity = horizGravity;
        if (Build.VERSION.SDK_INT >= 18) {
            handleBlurBackground();
        }
        int x2 = calculateX(anchor, horizGravity, this.mWidth, this.mOffsetX);
        int y2 = calculateY(anchor, vertGravity, this.mHeight, this.mOffsetY);
        if (this.isNeedReMeasureWH) {
            registerOnGlobalLayoutListener();
        }
        PopupWindowCompat.showAsDropDown(this.mPopupWindow, anchor, x2, y2, 0);
    }

    private int calculateY(View anchor, int vertGravity, int measuredH, int y) {
        if (vertGravity == 0) {
            return y - ((anchor.getHeight() / 2) + (measuredH / 2));
        }
        if (vertGravity == 1) {
            return y - (anchor.getHeight() + measuredH);
        }
        if (vertGravity == 3) {
            return y - anchor.getHeight();
        }
        if (vertGravity == 4) {
            return y - measuredH;
        }
        return y;
    }

    private int calculateX(View anchor, int horizGravity, int measuredW, int x) {
        if (horizGravity == 0) {
            return x + ((anchor.getWidth() / 2) - (measuredW / 2));
        }
        if (horizGravity != 1) {
            if (horizGravity == 2) {
                return x + anchor.getWidth();
            }
            if (horizGravity == 4) {
                return x - (measuredW - anchor.getWidth());
            }
            return x;
        }
        return x - measuredW;
    }

    public T setOnDismissListener(PopupWindow.OnDismissListener onDismissListener) {
        this.mOnDismissListener = onDismissListener;
        return (T) self();
    }

    public T setOnRealWHAlreadyListener(OnRealWHAlreadyListener onRealWHAlreadyListener) {
        this.mOnRealWHAlreadyListener = onRealWHAlreadyListener;
        return (T) self();
    }

    private void handleBackgroundDim() {
        if (Build.VERSION.SDK_INT < 18 || !this.isBackgroundDim) {
            return;
        }
        ViewGroup viewGroup = this.mDimView;
        if (viewGroup != null) {
            applyDim(viewGroup);
        } else if (getContentView() != null && getContentView().getContext() != null && (getContentView().getContext() instanceof Activity)) {
            Activity activity = (Activity) getContentView().getContext();
            applyDim(activity);
        }
    }

    private void handleBlurBackground() {
        if (this.isBlurBackground && Build.VERSION.SDK_INT >= 17) {
            ViewGroup viewGroup = this.mDimView;
            if (viewGroup != null) {
                applyBlurDim(viewGroup);
            } else if (getContentView() != null && getContentView().getContext() != null && (getContentView().getContext() instanceof Activity)) {
                Activity activity = (Activity) getContentView().getContext();
                applyBlurDim(activity);
            }
        }
    }

    private void applyBlurDim(Activity activity) {
        ViewGroup parent = (ViewGroup) activity.getWindow().getDecorView().getRootView();
        Bitmap bitmap = BlurKit.getInstance().fastBlur(parent, 10, 0.25f);
        Drawable dimDrawable = new BitmapDrawable((Resources) null, bitmap);
        dimDrawable.setBounds(0, 0, parent.getWidth(), parent.getHeight());
        ViewGroupOverlay overlay = parent.getOverlay();
        overlay.add(dimDrawable);
    }

    private void applyBlurDim(ViewGroup dimView) {
        Bitmap bitmap = BlurKit.getInstance().fastBlur(dimView, 10, 0.25f);
        Drawable dimDrawable = new BitmapDrawable((Resources) null, bitmap);
        ViewGroupOverlay overlay = dimView.getOverlay();
        overlay.add(dimDrawable);
    }

    private void applyDim(Activity activity) {
        ViewGroup parent = (ViewGroup) activity.getWindow().getDecorView().getRootView();
        Drawable dimDrawable = new ColorDrawable(this.mDimColor);
        dimDrawable.setBounds(0, 0, parent.getWidth(), parent.getHeight());
        dimDrawable.setAlpha((int) (this.mDimValue * 255.0f));
        ViewGroupOverlay overlay = parent.getOverlay();
        overlay.add(dimDrawable);
    }

    private void applyDim(ViewGroup dimView) {
        Drawable dimDrawable = new ColorDrawable(this.mDimColor);
        dimDrawable.setBounds(0, 0, dimView.getWidth(), dimView.getHeight());
        dimDrawable.setAlpha((int) (this.mDimValue * 255.0f));
        ViewGroupOverlay overlay = dimView.getOverlay();
        overlay.add(dimDrawable);
    }

    private void clearBackgroundDim() {
        Activity activity;
        if (Build.VERSION.SDK_INT >= 18) {
            if (this.isBackgroundDim || this.isBlurBackground) {
                ViewGroup viewGroup = this.mDimView;
                if (viewGroup != null) {
                    clearDim(viewGroup);
                } else if (getContentView() != null && (activity = (Activity) getContentView().getContext()) != null) {
                    clearDim(activity);
                }
            }
        }
    }

    private void clearDim(Activity activity) {
        ViewGroup parent = (ViewGroup) activity.getWindow().getDecorView().getRootView();
        ViewGroupOverlay overlay = parent.getOverlay();
        overlay.clear();
    }

    private void clearDim(ViewGroup dimView) {
        ViewGroupOverlay overlay = dimView.getOverlay();
        overlay.clear();
    }

    public View getContentView() {
        PopupWindow popupWindow = this.mPopupWindow;
        if (popupWindow != null) {
            return popupWindow.getContentView();
        }
        return null;
    }

    public PopupWindow getPopupWindow() {
        return this.mPopupWindow;
    }

    public int getWidth() {
        return this.mWidth;
    }

    public int getHeight() {
        return this.mHeight;
    }

    public int getXGravity() {
        return this.mXGravity;
    }

    public int getYGravity() {
        return this.mYGravity;
    }

    public int getOffsetX() {
        return this.mOffsetX;
    }

    public int getOffsetY() {
        return this.mOffsetY;
    }

    public boolean isShowing() {
        PopupWindow popupWindow = this.mPopupWindow;
        return popupWindow != null && popupWindow.isShowing();
    }

    public boolean isRealWHAlready() {
        return this.isRealWHAlready;
    }

    /* JADX WARN: Incorrect return type in method signature: <T:Landroid/view/View;>(I)TT; */
    public View findViewById(int viewId) {
        if (getContentView() == null) {
            return null;
        }
        View view = getContentView().findViewById(viewId);
        return view;
    }

    public void dismiss() {
        PopupWindow popupWindow = this.mPopupWindow;
        if (popupWindow != null) {
            popupWindow.dismiss();
        }
    }

    @Override // android.widget.PopupWindow.OnDismissListener
    public void onDismiss() {
        handleDismiss();
    }

    private void handleDismiss() {
        PopupWindow.OnDismissListener onDismissListener = this.mOnDismissListener;
        if (onDismissListener != null) {
            onDismissListener.onDismiss();
        }
        clearBackgroundDim();
        PopupWindow popupWindow = this.mPopupWindow;
        if (popupWindow != null && popupWindow.isShowing()) {
            this.mPopupWindow.dismiss();
        }
        onPopupWindowDismiss();
    }
}
