package androidx.recyclerview.widget;

import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class LayoutState {
    public static final int INVALID_LAYOUT = Integer.MIN_VALUE;
    public static final int ITEM_DIRECTION_HEAD = -1;
    public static final int ITEM_DIRECTION_TAIL = 1;
    public static final int LAYOUT_END = 1;
    public static final int LAYOUT_START = -1;
    public int mAvailable;
    public int mCurrentPosition;
    public boolean mInfinite;
    public int mItemDirection;
    public int mLayoutDirection;
    public boolean mStopInFocusable;
    public boolean mRecycle = true;
    public int mStartLine = 0;
    public int mEndLine = 0;

    public boolean hasMore(RecyclerView.State state) {
        int i2 = this.mCurrentPosition;
        return i2 >= 0 && i2 < state.getItemCount();
    }

    public View next(RecyclerView.Recycler recycler) {
        View viewForPosition = recycler.getViewForPosition(this.mCurrentPosition);
        this.mCurrentPosition += this.mItemDirection;
        return viewForPosition;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("LayoutState{mAvailable=");
        m586H.append(this.mAvailable);
        m586H.append(", mCurrentPosition=");
        m586H.append(this.mCurrentPosition);
        m586H.append(", mItemDirection=");
        m586H.append(this.mItemDirection);
        m586H.append(", mLayoutDirection=");
        m586H.append(this.mLayoutDirection);
        m586H.append(", mStartLine=");
        m586H.append(this.mStartLine);
        m586H.append(", mEndLine=");
        return C1499a.m579A(m586H, this.mEndLine, '}');
    }
}
