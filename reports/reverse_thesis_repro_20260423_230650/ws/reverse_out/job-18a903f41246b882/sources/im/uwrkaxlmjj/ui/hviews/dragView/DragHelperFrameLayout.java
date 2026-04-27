package im.uwrkaxlmjj.ui.hviews.dragView;

import android.content.Context;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import androidx.customview.widget.ViewDragHelper;
import im.uwrkaxlmjj.messenger.BuildVars;

/* JADX INFO: loaded from: classes5.dex */
public class DragHelperFrameLayout extends FrameLayout {
    protected DragCallBack mDragCallBack;
    protected boolean mDragEnable;
    protected ViewDragHelper mHelper;

    public DragHelperFrameLayout(Context context) {
        this(context, null);
    }

    public DragHelperFrameLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public DragHelperFrameLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mDragEnable = true;
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent event) {
        if (this.mDragEnable) {
            boolean isInView = isTouchCaptureView(event);
            ViewDragHelper viewDragHelper = this.mHelper;
            boolean result = viewDragHelper != null && viewDragHelper.shouldInterceptTouchEvent(event) && isInView;
            return result ? result : super.onInterceptTouchEvent(event);
        }
        boolean isInView2 = super.onInterceptTouchEvent(event);
        return isInView2;
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchTouchEvent(MotionEvent ev) {
        return super.dispatchTouchEvent(ev);
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        if (this.mDragEnable) {
            boolean tag = isTouchCaptureView(event);
            ViewDragHelper viewDragHelper = this.mHelper;
            if (viewDragHelper != null) {
                viewDragHelper.processTouchEvent(event);
            }
            return tag || super.onTouchEvent(event);
        }
        boolean tag2 = super.onTouchEvent(event);
        return tag2;
    }

    @Override // android.view.View
    public boolean performClick() {
        return super.performClick();
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        DragCallBack dragCallBack = this.mDragCallBack;
        if (dragCallBack != null && dragCallBack.isCapturedViewPositionHasChanged()) {
            for (int i = 0; i < getChildCount(); i++) {
                View child = getChildAt(i);
                if (child == this.mDragCallBack.getCapturedView()) {
                    log("onLayout", " before child  = " + child + " , left = " + child.getLeft() + " , top = " + child.getTop() + " , right = " + child.getRight() + " , bottom = " + child.getBottom());
                    int mw = child.getMeasuredWidth();
                    int mh = child.getMeasuredHeight();
                    int nl = this.mDragCallBack.getCapturedViewLastLeft();
                    int nt = this.mDragCallBack.getCapturedViewLastTop();
                    int nr = this.mDragCallBack.getCapturedViewLastRight();
                    int nb = this.mDragCallBack.getCapturedViewLastBottom();
                    if (nl < 0) {
                        nl = 0;
                        nr = mw;
                    } else if (nl + mw > getMeasuredWidth()) {
                        nl = getMeasuredWidth() - mw;
                        nr = nl + mw;
                    }
                    if (nr - nl < mw) {
                        nr = nl + mw;
                    }
                    if (nt < 0) {
                        nt = 0;
                        nb = mh;
                    } else if (nt + mh > getMeasuredHeight()) {
                        nt = getMeasuredHeight() - mh;
                        nb = nt + mh;
                    }
                    if (nb - nt < mh) {
                        nb = nt + mh;
                    }
                    child.layout(nl, nt, nr, nb);
                    log("onLayout", " after child  = " + child + " , left = " + child.getLeft() + " , top = " + child.getTop() + " , right = " + child.getRight() + " , bottom = " + child.getBottom());
                }
            }
        }
    }

    @Override // android.view.View
    public void computeScroll() {
        ViewDragHelper viewDragHelper = this.mHelper;
        if (viewDragHelper != null && viewDragHelper.continueSettling(true)) {
            invalidate();
        }
    }

    public boolean isTouchCaptureView(MotionEvent event) {
        int action = event.getAction();
        if (action != 0 && action != 1 && action != 2 && action != 3) {
            return false;
        }
        float x = event.getX();
        float y = event.getY();
        DragCallBack dragCallBack = this.mDragCallBack;
        if (dragCallBack == null || dragCallBack.getCapturedView() == null) {
            return false;
        }
        View captureView = this.mDragCallBack.getCapturedView();
        if (x < captureView.getLeft() || x > captureView.getRight() || y < captureView.getTop() || y > captureView.getBottom()) {
            return false;
        }
        return true;
    }

    public void setDragEnable(boolean dragEnable) {
        this.mDragEnable = dragEnable;
    }

    public void setViewDragCallBack(DragCallBack callBack) {
        setViewDragCallBack(1.0f, callBack);
    }

    public void setViewDragCallBack(float sensitivity, DragCallBack callBack) {
        this.mDragCallBack = callBack;
        if (callBack == null) {
            return;
        }
        ViewDragHelper viewDragHelperCreate = ViewDragHelper.create(this, sensitivity, callBack);
        this.mHelper = viewDragHelperCreate;
        this.mDragCallBack.setHelper(viewDragHelperCreate);
    }

    public DragCallBack getViewDragCallBack() {
        return this.mDragCallBack;
    }

    public ViewDragHelper getViewDragHelper() {
        return this.mHelper;
    }

    public void setEdgeTrackingEnabled(int edgeFlags) {
        ViewDragHelper viewDragHelper = this.mHelper;
        if (viewDragHelper != null) {
            viewDragHelper.setEdgeTrackingEnabled(edgeFlags);
        }
    }

    public void log(String desc, String msg) {
        if (BuildVars.DEBUG_VERSION) {
            Log.i("DragHelperFrame", "DragHelperFrameLayout ===> " + desc + "  " + msg);
        }
    }
}
