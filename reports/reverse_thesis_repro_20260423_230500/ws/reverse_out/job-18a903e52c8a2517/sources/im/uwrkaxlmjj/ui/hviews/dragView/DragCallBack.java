package im.uwrkaxlmjj.ui.hviews.dragView;

import android.graphics.Rect;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import androidx.customview.widget.ViewDragHelper;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class DragCallBack extends ViewDragHelper.Callback {
    public static final int SIDE_BOTTOM = 4;
    public static final int SIDE_LEFT = 1;
    public static final int SIDE_NONE = 0;
    public static final int SIDE_RIGHT = 3;
    public static final int SIDE_TOP = 2;
    protected boolean mAllowSideToTopOrBottom;
    protected boolean mAllowTopToStatusBar;
    protected View mCapturedView;
    protected int mCapturedViewLastBottom;
    protected int mCapturedViewLastLeft;
    protected int mCapturedViewLastRight;
    protected int mCapturedViewLastTop;
    protected boolean mCapturedViewPositionHasChanged;
    protected ViewDragHelper mHelper;
    protected boolean mIsDraging;
    protected List<Rect> mNotchRects;
    protected View mParent;
    protected boolean mAllowDragOutParentBorder = false;
    protected boolean mAutoBackBorderAfterRelease = true;
    protected int mCloseToSideWhenViewRealeased = 0;

    @Retention(RetentionPolicy.SOURCE)
    @interface ColseToSide {
    }

    public DragCallBack(View parent, View capturedView) {
        this.mParent = parent;
        this.mCapturedView = capturedView;
    }

    @Override // androidx.customview.widget.ViewDragHelper.Callback
    public boolean tryCaptureView(View child, int pointerId) {
        this.mCloseToSideWhenViewRealeased = 0;
        boolean result = this.mCapturedView == child;
        if (result) {
            this.mIsDraging = result;
        }
        return result;
    }

    @Override // androidx.customview.widget.ViewDragHelper.Callback
    public int clampViewPositionHorizontal(View child, int left, int dx) {
        if (this.mParent != null && !this.mAllowDragOutParentBorder && (child.getLayoutParams() instanceof ViewGroup.MarginLayoutParams)) {
            ViewGroup.MarginLayoutParams lp = (ViewGroup.MarginLayoutParams) child.getLayoutParams();
            int leftBorder = this.mParent.getPaddingLeft() + lp.leftMargin;
            int rightBorder = ((this.mParent.getMeasuredWidth() - this.mParent.getPaddingRight()) - child.getMeasuredWidth()) - lp.rightMargin;
            return Math.min(Math.max(leftBorder, left), rightBorder);
        }
        return left;
    }

    @Override // androidx.customview.widget.ViewDragHelper.Callback
    public int clampViewPositionVertical(View child, int top, int dy) {
        if (this.mParent != null && !this.mAllowDragOutParentBorder && (child.getLayoutParams() instanceof ViewGroup.MarginLayoutParams)) {
            ViewGroup.MarginLayoutParams lp = (ViewGroup.MarginLayoutParams) child.getLayoutParams();
            int topBorder = this.mParent.getPaddingTop() + lp.topMargin;
            int bottomBorder = ((this.mParent.getMeasuredHeight() - this.mParent.getPaddingBottom()) - child.getMeasuredHeight()) - lp.bottomMargin;
            return Math.min(Math.max(topBorder, top), bottomBorder);
        }
        return top;
    }

    @Override // androidx.customview.widget.ViewDragHelper.Callback
    public int getViewHorizontalDragRange(View child) {
        View view = this.mParent;
        if (view != null) {
            return view.getMeasuredWidth() - child.getMeasuredWidth();
        }
        return 0;
    }

    @Override // androidx.customview.widget.ViewDragHelper.Callback
    public int getViewVerticalDragRange(View child) {
        View view = this.mParent;
        if (view != null) {
            return view.getMeasuredHeight() - child.getMeasuredHeight();
        }
        return 0;
    }

    @Override // androidx.customview.widget.ViewDragHelper.Callback
    public void onViewPositionChanged(View changedView, int left, int top, int dx, int dy) {
        super.onViewPositionChanged(changedView, left, top, dx, dy);
        this.mCapturedViewPositionHasChanged = true;
        this.mCapturedViewLastLeft = left;
        this.mCapturedViewLastTop = top;
        this.mCapturedViewLastRight = changedView.getRight();
        int bottom = changedView.getBottom();
        this.mCapturedViewLastBottom = bottom;
        changedView.layout(this.mCapturedViewLastLeft, this.mCapturedViewLastTop, this.mCapturedViewLastRight, bottom);
        log("onViewPositionChanged", "child  = " + changedView + " , left = " + left + " , top = " + top + " , right = " + this.mCapturedViewLastRight + " , bottom = " + this.mCapturedViewLastBottom);
    }

    @Override // androidx.customview.widget.ViewDragHelper.Callback
    public void onViewReleased(View releasedChild, float xvel, float yvel) {
        int left;
        int top;
        boolean toTB = false;
        this.mIsDraging = false;
        super.onViewReleased(releasedChild, xvel, yvel);
        if (this.mAutoBackBorderAfterRelease && releasedChild == this.mCapturedView && this.mParent != null) {
            int dXY = Math.min(releasedChild.getLeft(), this.mParent.getRight() - releasedChild.getRight());
            int dTB = Math.min(releasedChild.getTop(), this.mParent.getBottom() - releasedChild.getBottom());
            if (dTB <= dXY && this.mAllowSideToTopOrBottom) {
                toTB = true;
            }
            if (toTB) {
                left = releasedChild.getLeft();
                if (releasedChild.getTop() <= this.mParent.getBottom() - releasedChild.getBottom()) {
                    if (this.mAllowTopToStatusBar) {
                        top = 0;
                    } else {
                        top = AndroidUtilities.statusBarHeight;
                    }
                    this.mCloseToSideWhenViewRealeased = 2;
                } else {
                    int top2 = this.mParent.getBottom() - releasedChild.getMeasuredHeight();
                    this.mCloseToSideWhenViewRealeased = 4;
                    top = top2;
                }
            } else {
                int top3 = releasedChild.getTop();
                if (releasedChild.getLeft() <= this.mParent.getRight() - releasedChild.getRight()) {
                    this.mCloseToSideWhenViewRealeased = 1;
                    left = 0;
                    top = top3;
                } else {
                    left = this.mParent.getRight() - releasedChild.getMeasuredWidth();
                    this.mCloseToSideWhenViewRealeased = 4;
                    top = top3;
                }
            }
            if (this.mHelper != null) {
                List<Rect> list = this.mNotchRects;
                if (list != null && list.size() > 0) {
                    calculateForNotchRects(toTB, left, top);
                } else if (this.mNotchRects == null) {
                    this.mNotchRects = getNotchRectList();
                }
                this.mHelper.settleCapturedViewAt(left, top);
                this.mParent.invalidate();
                log("onViewReleased ", "releasedChild  = " + releasedChild + " , left = " + releasedChild.getLeft() + " , top = " + releasedChild.getTop() + " , right = " + releasedChild.getRight() + " , bottom = " + releasedChild.getBottom());
            }
        }
    }

    @Override // androidx.customview.widget.ViewDragHelper.Callback
    public void onEdgeDragStarted(int edgeFlags, int pointerId) {
        super.onEdgeDragStarted(edgeFlags, pointerId);
    }

    public List<Rect> getNotchRectList() {
        return new ArrayList();
    }

    public void calculateForNotchRects(boolean toTB, int left, int top) {
        if (this.mNotchRects.size() > 0) {
            for (Rect rect : this.mNotchRects) {
                if (left >= rect.left && left <= rect.right && top >= rect.top && top <= rect.bottom) {
                    left = rect.left;
                    top = rect.top;
                }
            }
        }
    }

    public DragCallBack setHelper(ViewDragHelper mHelper) {
        this.mHelper = mHelper;
        return this;
    }

    public DragCallBack setAllowSideToTopOrBottom(boolean allowSideToTopOrBottom) {
        this.mAllowSideToTopOrBottom = allowSideToTopOrBottom;
        return this;
    }

    public DragCallBack setAllowDragOutParentBorder(boolean allowDragOutParentBorder) {
        this.mAllowDragOutParentBorder = allowDragOutParentBorder;
        return this;
    }

    public DragCallBack setAutoBackBorderAfterRelease(boolean autoBackBorderAfterRelease) {
        this.mAutoBackBorderAfterRelease = autoBackBorderAfterRelease;
        return this;
    }

    public DragCallBack setAllowTopToStatusBar(boolean mAllowTopToStatusBar) {
        this.mAllowTopToStatusBar = mAllowTopToStatusBar;
        return this;
    }

    public boolean isAllowDragOutParentBorder() {
        return this.mAllowDragOutParentBorder;
    }

    public boolean isAutoBackBorderAfterRelease() {
        return this.mAutoBackBorderAfterRelease;
    }

    public boolean isCapturedViewPositionHasChanged() {
        return this.mCapturedViewPositionHasChanged;
    }

    public boolean isDraging() {
        return this.mIsDraging;
    }

    public View getCapturedView() {
        return this.mCapturedView;
    }

    public int getCapturedViewLastLeft() {
        return this.mCapturedViewLastLeft;
    }

    public int getCapturedViewLastTop() {
        return this.mCapturedViewLastTop;
    }

    public int getCapturedViewLastRight() {
        return this.mCapturedViewLastRight;
    }

    public int getCapturedViewLastBottom() {
        return this.mCapturedViewLastBottom;
    }

    public int getCloseToSideWhenViewRealeased() {
        return this.mCloseToSideWhenViewRealeased;
    }

    public void log(String desc, String msg) {
        if (BuildVars.DEBUG_VERSION) {
            Log.i("DragHelperFrame", "DragCallBack ===> " + desc + msg);
        }
    }
}
