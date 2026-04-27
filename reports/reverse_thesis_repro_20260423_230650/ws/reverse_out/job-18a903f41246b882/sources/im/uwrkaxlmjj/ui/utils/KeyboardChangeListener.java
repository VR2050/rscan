package im.uwrkaxlmjj.ui.utils;

import android.R;
import android.app.Activity;
import android.graphics.Rect;
import android.view.View;
import android.view.ViewTreeObserver;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class KeyboardChangeListener implements ViewTreeObserver.OnGlobalLayoutListener {
    private View mContentView;
    private boolean mIsDestroy;
    private int mKeyBoardHeight;
    private KeyBoardListener mKeyBoardListener;
    private int mLastKeyBoardHeight;
    private int mOriginHeight;
    private int mPreHeight;
    private Rect mRect;

    public interface KeyBoardListener {
        void onKeyboardChange(boolean z, int i);
    }

    public void setKeyBoardListener(KeyBoardListener keyBoardListen) {
        this.mKeyBoardListener = keyBoardListen;
    }

    public KeyboardChangeListener(Activity contextObj) {
        if (contextObj == null) {
            return;
        }
        init(findContentView(contextObj));
    }

    public KeyboardChangeListener(View view) {
        init(view);
    }

    private void init(View view) {
        if (view == null) {
            return;
        }
        this.mContentView = view;
        if (view != null) {
            this.mRect = new Rect();
            addContentTreeObserver();
        }
    }

    private View findContentView(Activity contextObj) {
        return contextObj.findViewById(R.id.content);
    }

    private void addContentTreeObserver() {
        this.mContentView.getViewTreeObserver().addOnGlobalLayoutListener(this);
    }

    public void destroy() {
        this.mIsDestroy = true;
        View view = this.mContentView;
        if (view != null && view.getViewTreeObserver() != null) {
            this.mContentView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
            this.mContentView = null;
        }
        this.mRect = null;
        this.mKeyBoardListener = null;
        this.mOriginHeight = 0;
        this.mPreHeight = 0;
        this.mKeyBoardHeight = 0;
        this.mLastKeyBoardHeight = 0;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        int currHeight;
        boolean isShow;
        if (this.mIsDestroy || (currHeight = this.mContentView.getHeight()) == 0) {
            return;
        }
        boolean hasChange = false;
        int keyBoardHeight = 0;
        if (this.mPreHeight == 0) {
            this.mPreHeight = currHeight;
            this.mOriginHeight = currHeight;
        } else {
            keyBoardHeight = getKeyboardHeight();
            if (this.mPreHeight != currHeight) {
                hasChange = true;
                this.mPreHeight = currHeight;
                if (keyBoardHeight == 0) {
                    keyBoardHeight = this.mOriginHeight - currHeight;
                }
            } else {
                int keyBoardHeight2 = this.mLastKeyBoardHeight;
                hasChange = keyBoardHeight != keyBoardHeight2;
            }
            this.mLastKeyBoardHeight = keyBoardHeight;
        }
        if (hasChange) {
            int i = this.mOriginHeight;
            if (i == this.mPreHeight) {
                if (keyBoardHeight > 0) {
                    isShow = true;
                } else {
                    isShow = false;
                }
            } else {
                if (keyBoardHeight == 0) {
                    keyBoardHeight = i - currHeight;
                }
                isShow = keyBoardHeight > 0;
            }
            if (this.mKeyBoardHeight == 0) {
                this.mKeyBoardHeight = keyBoardHeight;
            }
            KeyBoardListener keyBoardListener = this.mKeyBoardListener;
            if (keyBoardListener != null) {
                keyBoardListener.onKeyboardChange(isShow, this.mKeyBoardHeight);
            }
        }
    }

    public int getKeyboardHeight() {
        this.mContentView.getWindowVisibleDisplayFrame(this.mRect);
        if (this.mRect.bottom == 0 && this.mRect.top == 0) {
            return 0;
        }
        int usableViewHeight = (this.mContentView.getHeight() - (this.mRect.top != 0 ? AndroidUtilities.statusBarHeight : 0)) - AndroidUtilities.getViewInset(this.mContentView);
        return Math.max(0, usableViewHeight - (this.mRect.bottom - this.mRect.top));
    }
}
