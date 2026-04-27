package com.gyf.barlibrary;

import android.app.Activity;
import android.app.Dialog;
import android.graphics.Rect;
import android.os.Build;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.Window;
import android.widget.FrameLayout;

/* JADX INFO: loaded from: classes.dex */
public class KeyboardPatch {
    private int actionBarHeight;
    private int keyboardHeightPrevious;
    private Activity mActivity;
    private BarParams mBarParams;
    private View mChildView;
    private View mContentView;
    private View mDecorView;
    private Window mWindow;
    private boolean navigationAtBottom;
    private int navigationBarHeight;
    private ViewTreeObserver.OnGlobalLayoutListener onGlobalLayoutListener;
    private int paddingBottom;
    private int paddingLeft;
    private int paddingRight;
    private int paddingTop;
    private int statusBarHeight;

    private KeyboardPatch(Activity activity) {
        this(activity, ((FrameLayout) activity.getWindow().getDecorView().findViewById(android.R.id.content)).getChildAt(0));
    }

    private KeyboardPatch(Activity activity, View contentView) {
        this(activity, null, "", contentView);
    }

    private KeyboardPatch(Activity activity, Dialog dialog, String tag) {
        this(activity, dialog, tag, dialog.getWindow().findViewById(android.R.id.content));
    }

    private KeyboardPatch(Activity activity, Dialog dialog, String tag, View contentView) {
        this.onGlobalLayoutListener = new ViewTreeObserver.OnGlobalLayoutListener() { // from class: com.gyf.barlibrary.KeyboardPatch.1
            @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
            public void onGlobalLayout() {
                int keyboardHeight;
                int keyboardHeight2;
                if (!KeyboardPatch.this.navigationAtBottom) {
                    return;
                }
                Rect r = new Rect();
                KeyboardPatch.this.mDecorView.getWindowVisibleDisplayFrame(r);
                boolean isPopup = false;
                if (KeyboardPatch.this.mBarParams.systemWindows) {
                    int keyboardHeight3 = (KeyboardPatch.this.mContentView.getHeight() - r.bottom) - KeyboardPatch.this.navigationBarHeight;
                    if (KeyboardPatch.this.mBarParams.onKeyboardListener != null) {
                        if (keyboardHeight3 > KeyboardPatch.this.navigationBarHeight) {
                            isPopup = true;
                        }
                        KeyboardPatch.this.mBarParams.onKeyboardListener.onKeyboardChange(isPopup, keyboardHeight3);
                        return;
                    }
                    return;
                }
                if (KeyboardPatch.this.mChildView != null) {
                    int diff = KeyboardPatch.this.mBarParams.isSupportActionBar ? ((KeyboardPatch.this.mContentView.getHeight() + KeyboardPatch.this.statusBarHeight) + KeyboardPatch.this.actionBarHeight) - r.bottom : KeyboardPatch.this.mBarParams.fits ? (KeyboardPatch.this.mContentView.getHeight() + KeyboardPatch.this.statusBarHeight) - r.bottom : KeyboardPatch.this.mContentView.getHeight() - r.bottom;
                    if (KeyboardPatch.this.mBarParams.fullScreen) {
                        keyboardHeight2 = diff - KeyboardPatch.this.navigationBarHeight;
                    } else {
                        keyboardHeight2 = diff;
                    }
                    if (KeyboardPatch.this.mBarParams.fullScreen && diff == KeyboardPatch.this.navigationBarHeight) {
                        diff -= KeyboardPatch.this.navigationBarHeight;
                    }
                    if (keyboardHeight2 != KeyboardPatch.this.keyboardHeightPrevious) {
                        KeyboardPatch.this.mContentView.setPadding(KeyboardPatch.this.paddingLeft, KeyboardPatch.this.paddingTop, KeyboardPatch.this.paddingRight, KeyboardPatch.this.paddingBottom + diff);
                        KeyboardPatch.this.keyboardHeightPrevious = keyboardHeight2;
                        if (KeyboardPatch.this.mBarParams.onKeyboardListener != null) {
                            if (keyboardHeight2 > KeyboardPatch.this.navigationBarHeight) {
                                isPopup = true;
                            }
                            KeyboardPatch.this.mBarParams.onKeyboardListener.onKeyboardChange(isPopup, keyboardHeight2);
                            return;
                        }
                        return;
                    }
                    return;
                }
                int diff2 = KeyboardPatch.this.mContentView.getHeight() - r.bottom;
                if (KeyboardPatch.this.mBarParams.navigationBarEnable && KeyboardPatch.this.mBarParams.navigationBarWithKitkatEnable) {
                    keyboardHeight = (Build.VERSION.SDK_INT == 19 || OSUtils.isEMUI3_1() || KeyboardPatch.this.mBarParams.fullScreen) ? diff2 - KeyboardPatch.this.navigationBarHeight : diff2;
                    if (KeyboardPatch.this.mBarParams.fullScreen && diff2 == KeyboardPatch.this.navigationBarHeight) {
                        diff2 -= KeyboardPatch.this.navigationBarHeight;
                    }
                } else {
                    keyboardHeight = diff2;
                }
                if (keyboardHeight != KeyboardPatch.this.keyboardHeightPrevious) {
                    if (KeyboardPatch.this.mBarParams.isSupportActionBar) {
                        KeyboardPatch.this.mContentView.setPadding(0, KeyboardPatch.this.statusBarHeight + KeyboardPatch.this.actionBarHeight, 0, diff2);
                    } else if (KeyboardPatch.this.mBarParams.fits) {
                        KeyboardPatch.this.mContentView.setPadding(0, KeyboardPatch.this.statusBarHeight, 0, diff2);
                    } else {
                        KeyboardPatch.this.mContentView.setPadding(0, 0, 0, diff2);
                    }
                    KeyboardPatch.this.keyboardHeightPrevious = keyboardHeight;
                    if (KeyboardPatch.this.mBarParams.onKeyboardListener != null) {
                        if (keyboardHeight > KeyboardPatch.this.navigationBarHeight) {
                            isPopup = true;
                        }
                        KeyboardPatch.this.mBarParams.onKeyboardListener.onKeyboardChange(isPopup, keyboardHeight);
                    }
                }
            }
        };
        this.mActivity = activity;
        Window window = dialog != null ? dialog.getWindow() : activity.getWindow();
        this.mWindow = window;
        this.mDecorView = window.getDecorView();
        this.mContentView = contentView != null ? contentView : this.mWindow.getDecorView().findViewById(android.R.id.content);
        BarParams barParams = dialog != null ? ImmersionBar.with(activity, dialog, tag).getBarParams() : ImmersionBar.with(activity).getBarParams();
        this.mBarParams = barParams;
        if (barParams == null) {
            throw new IllegalArgumentException("先使用ImmersionBar初始化");
        }
    }

    private KeyboardPatch(Activity activity, Window window) {
        this.onGlobalLayoutListener = new ViewTreeObserver.OnGlobalLayoutListener() { // from class: com.gyf.barlibrary.KeyboardPatch.1
            @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
            public void onGlobalLayout() {
                int keyboardHeight;
                int keyboardHeight2;
                if (!KeyboardPatch.this.navigationAtBottom) {
                    return;
                }
                Rect r = new Rect();
                KeyboardPatch.this.mDecorView.getWindowVisibleDisplayFrame(r);
                boolean isPopup = false;
                if (KeyboardPatch.this.mBarParams.systemWindows) {
                    int keyboardHeight3 = (KeyboardPatch.this.mContentView.getHeight() - r.bottom) - KeyboardPatch.this.navigationBarHeight;
                    if (KeyboardPatch.this.mBarParams.onKeyboardListener != null) {
                        if (keyboardHeight3 > KeyboardPatch.this.navigationBarHeight) {
                            isPopup = true;
                        }
                        KeyboardPatch.this.mBarParams.onKeyboardListener.onKeyboardChange(isPopup, keyboardHeight3);
                        return;
                    }
                    return;
                }
                if (KeyboardPatch.this.mChildView != null) {
                    int diff = KeyboardPatch.this.mBarParams.isSupportActionBar ? ((KeyboardPatch.this.mContentView.getHeight() + KeyboardPatch.this.statusBarHeight) + KeyboardPatch.this.actionBarHeight) - r.bottom : KeyboardPatch.this.mBarParams.fits ? (KeyboardPatch.this.mContentView.getHeight() + KeyboardPatch.this.statusBarHeight) - r.bottom : KeyboardPatch.this.mContentView.getHeight() - r.bottom;
                    if (KeyboardPatch.this.mBarParams.fullScreen) {
                        keyboardHeight2 = diff - KeyboardPatch.this.navigationBarHeight;
                    } else {
                        keyboardHeight2 = diff;
                    }
                    if (KeyboardPatch.this.mBarParams.fullScreen && diff == KeyboardPatch.this.navigationBarHeight) {
                        diff -= KeyboardPatch.this.navigationBarHeight;
                    }
                    if (keyboardHeight2 != KeyboardPatch.this.keyboardHeightPrevious) {
                        KeyboardPatch.this.mContentView.setPadding(KeyboardPatch.this.paddingLeft, KeyboardPatch.this.paddingTop, KeyboardPatch.this.paddingRight, KeyboardPatch.this.paddingBottom + diff);
                        KeyboardPatch.this.keyboardHeightPrevious = keyboardHeight2;
                        if (KeyboardPatch.this.mBarParams.onKeyboardListener != null) {
                            if (keyboardHeight2 > KeyboardPatch.this.navigationBarHeight) {
                                isPopup = true;
                            }
                            KeyboardPatch.this.mBarParams.onKeyboardListener.onKeyboardChange(isPopup, keyboardHeight2);
                            return;
                        }
                        return;
                    }
                    return;
                }
                int diff2 = KeyboardPatch.this.mContentView.getHeight() - r.bottom;
                if (KeyboardPatch.this.mBarParams.navigationBarEnable && KeyboardPatch.this.mBarParams.navigationBarWithKitkatEnable) {
                    keyboardHeight = (Build.VERSION.SDK_INT == 19 || OSUtils.isEMUI3_1() || KeyboardPatch.this.mBarParams.fullScreen) ? diff2 - KeyboardPatch.this.navigationBarHeight : diff2;
                    if (KeyboardPatch.this.mBarParams.fullScreen && diff2 == KeyboardPatch.this.navigationBarHeight) {
                        diff2 -= KeyboardPatch.this.navigationBarHeight;
                    }
                } else {
                    keyboardHeight = diff2;
                }
                if (keyboardHeight != KeyboardPatch.this.keyboardHeightPrevious) {
                    if (KeyboardPatch.this.mBarParams.isSupportActionBar) {
                        KeyboardPatch.this.mContentView.setPadding(0, KeyboardPatch.this.statusBarHeight + KeyboardPatch.this.actionBarHeight, 0, diff2);
                    } else if (KeyboardPatch.this.mBarParams.fits) {
                        KeyboardPatch.this.mContentView.setPadding(0, KeyboardPatch.this.statusBarHeight, 0, diff2);
                    } else {
                        KeyboardPatch.this.mContentView.setPadding(0, 0, 0, diff2);
                    }
                    KeyboardPatch.this.keyboardHeightPrevious = keyboardHeight;
                    if (KeyboardPatch.this.mBarParams.onKeyboardListener != null) {
                        if (keyboardHeight > KeyboardPatch.this.navigationBarHeight) {
                            isPopup = true;
                        }
                        KeyboardPatch.this.mBarParams.onKeyboardListener.onKeyboardChange(isPopup, keyboardHeight);
                    }
                }
            }
        };
        this.mActivity = activity;
        this.mWindow = window;
        View decorView = window.getDecorView();
        this.mDecorView = decorView;
        FrameLayout frameLayout = (FrameLayout) decorView.findViewById(android.R.id.content);
        View childAt = frameLayout.getChildAt(0);
        this.mChildView = childAt;
        childAt = childAt == null ? frameLayout : childAt;
        this.mContentView = childAt;
        this.paddingLeft = childAt.getPaddingLeft();
        this.paddingTop = this.mContentView.getPaddingTop();
        this.paddingRight = this.mContentView.getPaddingRight();
        this.paddingBottom = this.mContentView.getPaddingBottom();
        BarConfig barConfig = new BarConfig(this.mActivity);
        this.statusBarHeight = barConfig.getStatusBarHeight();
        this.navigationBarHeight = barConfig.getNavigationBarHeight();
        this.actionBarHeight = barConfig.getActionBarHeight();
        this.navigationAtBottom = barConfig.isNavigationAtBottom();
    }

    public static KeyboardPatch patch(Activity activity) {
        return new KeyboardPatch(activity);
    }

    public static KeyboardPatch patch(Activity activity, View contentView) {
        return new KeyboardPatch(activity, contentView);
    }

    public static KeyboardPatch patch(Activity activity, Dialog dialog, String tag) {
        return new KeyboardPatch(activity, dialog, tag);
    }

    public static KeyboardPatch patch(Activity activity, Dialog dialog, String tag, View contentView) {
        return new KeyboardPatch(activity, dialog, tag, contentView);
    }

    protected static KeyboardPatch patch(Activity activity, Window window) {
        return new KeyboardPatch(activity, window);
    }

    protected void setBarParams(BarParams barParams) {
        this.mBarParams = barParams;
    }

    public void enable() {
        enable(18);
    }

    public void enable(int mode) {
        if (Build.VERSION.SDK_INT >= 19) {
            this.mWindow.setSoftInputMode(mode);
            this.mDecorView.getViewTreeObserver().addOnGlobalLayoutListener(this.onGlobalLayoutListener);
        }
    }

    public void disable() {
        disable(18);
    }

    public void disable(int mode) {
        if (Build.VERSION.SDK_INT >= 19) {
            this.mWindow.setSoftInputMode(mode);
            this.mDecorView.getViewTreeObserver().removeOnGlobalLayoutListener(this.onGlobalLayoutListener);
        }
    }
}
