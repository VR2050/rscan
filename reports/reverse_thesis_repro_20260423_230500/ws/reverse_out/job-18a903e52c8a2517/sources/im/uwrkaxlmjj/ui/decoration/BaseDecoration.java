package im.uwrkaxlmjj.ui.decoration;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.text.TextUtils;
import android.util.SparseIntArray;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.ui.decoration.ClickInfo;
import im.uwrkaxlmjj.ui.decoration.listener.OnGroupClickListener;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes5.dex */
public abstract class BaseDecoration extends RecyclerView.ItemDecoration {
    private GestureDetector gestureDetector;
    Paint mDividePaint;
    private boolean mDownInHeader;
    int mHeaderCount;
    protected OnGroupClickListener mOnGroupClickListener;
    int mGroupBackground = Color.parseColor("#48BDFF");
    int mGroupHeight = 120;
    int mDivideColor = Color.parseColor("#CCCCCC");
    int mDivideHeight = 0;
    private SparseIntArray firstInGroupCash = new SparseIntArray(100);
    private int offset = 0;
    protected HashMap<Integer, ClickInfo> stickyHeaderPosArray = new HashMap<>();
    private GestureDetector.OnGestureListener gestureListener = new GestureDetector.OnGestureListener() { // from class: im.uwrkaxlmjj.ui.decoration.BaseDecoration.3
        @Override // android.view.GestureDetector.OnGestureListener
        public boolean onDown(MotionEvent e) {
            return false;
        }

        @Override // android.view.GestureDetector.OnGestureListener
        public void onShowPress(MotionEvent e) {
        }

        @Override // android.view.GestureDetector.OnGestureListener
        public boolean onSingleTapUp(MotionEvent e) {
            return BaseDecoration.this.onTouchEvent(e);
        }

        @Override // android.view.GestureDetector.OnGestureListener
        public boolean onScroll(MotionEvent e1, MotionEvent e2, float distanceX, float distanceY) {
            return false;
        }

        @Override // android.view.GestureDetector.OnGestureListener
        public void onLongPress(MotionEvent e) {
        }

        @Override // android.view.GestureDetector.OnGestureListener
        public boolean onFling(MotionEvent e1, MotionEvent e2, float velocityX, float velocityY) {
            return false;
        }
    };

    abstract String getGroupName(int i);

    public BaseDecoration() {
        Paint paint = new Paint();
        this.mDividePaint = paint;
        paint.setColor(this.mDivideColor);
    }

    protected void setOnGroupClickListener(OnGroupClickListener listener) {
        this.mOnGroupClickListener = listener;
    }

    protected int getRealPosition(int position) {
        return position - this.mHeaderCount;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
        super.getItemOffsets(outRect, view, parent, state);
        int position = parent.getChildAdapterPosition(view);
        int realPosition = getRealPosition(position);
        RecyclerView.LayoutManager manager = parent.getLayoutManager();
        if (manager instanceof GridLayoutManager) {
            int spanCount = ((GridLayoutManager) manager).getSpanCount();
            if (!isHeader(realPosition) && !isOffset(realPosition)) {
                if (isFirstLineInGroup(realPosition, spanCount)) {
                    outRect.top = this.mGroupHeight;
                    return;
                } else {
                    outRect.top = this.mDivideHeight;
                    return;
                }
            }
            return;
        }
        if (!isHeader(realPosition) && !isOffset(realPosition)) {
            if (isFirstInGroup(realPosition)) {
                outRect.top = this.mGroupHeight;
            } else {
                outRect.top = this.mDivideHeight;
            }
        }
    }

    public void setOffset(int count) {
        this.offset = count;
    }

    protected boolean isFirstInGroup(int realPosition) {
        String preGroupId;
        if (realPosition < 0) {
            return false;
        }
        if (realPosition == 0) {
            return true;
        }
        if (realPosition <= 0) {
            preGroupId = null;
        } else {
            preGroupId = getGroupName(realPosition - 1);
        }
        String curGroupId = getGroupName(realPosition);
        if (curGroupId == null) {
            return false;
        }
        return !TextUtils.equals(preGroupId, curGroupId);
    }

    protected boolean isFirstInRecyclerView(int realPosition, int index) {
        return realPosition >= 0 && index == 0;
    }

    protected boolean isHeader(int realPosition) {
        return realPosition < 0;
    }

    protected boolean isOffset(int realPosition) {
        return realPosition < this.offset;
    }

    protected boolean isFirstLineInGroup(int realPosition, int spanCount) {
        if (realPosition < 0) {
            return false;
        }
        if (realPosition == 0) {
            return true;
        }
        int posFirstInGroup = getFirstInGroupWithCash(realPosition);
        if (realPosition - posFirstInGroup >= spanCount) {
            return false;
        }
        return true;
    }

    public void resetSpan(RecyclerView recyclerView, GridLayoutManager gridLayoutManager) {
        if (recyclerView == null) {
            throw new NullPointerException("recyclerView not allow null");
        }
        if (gridLayoutManager == null) {
            throw new NullPointerException("gridLayoutManager not allow null");
        }
        final int spanCount = gridLayoutManager.getSpanCount();
        GridLayoutManager.SpanSizeLookup lookup = new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.decoration.BaseDecoration.1
            @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
            public int getSpanSize(int position) {
                String nextGroupId;
                int realPosition = BaseDecoration.this.getRealPosition(position);
                if (realPosition < 0) {
                    int span = spanCount;
                    return span;
                }
                String curGroupId = BaseDecoration.this.getGroupName(realPosition);
                try {
                    nextGroupId = BaseDecoration.this.getGroupName(realPosition + 1);
                } catch (Exception e) {
                    nextGroupId = curGroupId;
                }
                if (!TextUtils.equals(curGroupId, nextGroupId)) {
                    int posFirstInGroup = BaseDecoration.this.getFirstInGroupWithCash(realPosition);
                    int i = spanCount;
                    return i - ((realPosition - posFirstInGroup) % i);
                }
                return 1;
            }
        };
        gridLayoutManager.setSpanSizeLookup(lookup);
    }

    public void onEventDown(MotionEvent event) {
        boolean z = false;
        if (event == null) {
            this.mDownInHeader = false;
            return;
        }
        if (event.getY() > 0.0f && event.getY() < this.mGroupHeight) {
            z = true;
        }
        this.mDownInHeader = z;
    }

    public boolean onEventUp(MotionEvent event) {
        if (this.mDownInHeader) {
            float y = event.getY();
            boolean isInHeader = y > 0.0f && y < ((float) this.mGroupHeight);
            if (isInHeader) {
                return onTouchEvent(event);
            }
        }
        return false;
    }

    protected int getFirstInGroupWithCash(int realPosition) {
        return getFirstInGroup(realPosition);
    }

    private int getFirstInGroup(int realPosition) {
        if (realPosition <= 0) {
            return 0;
        }
        if (isFirstInGroup(realPosition)) {
            return realPosition;
        }
        return getFirstInGroup(realPosition - 1);
    }

    protected boolean isLastLineInGroup(RecyclerView recyclerView, int realPosition) {
        String nextGroupName;
        if (realPosition < 0) {
            return true;
        }
        String curGroupName = getGroupName(realPosition);
        RecyclerView.LayoutManager manager = recyclerView.getLayoutManager();
        int findCount = 1;
        if (manager instanceof GridLayoutManager) {
            int spanCount = ((GridLayoutManager) manager).getSpanCount();
            int firstPositionInGroup = getFirstInGroupWithCash(realPosition);
            findCount = spanCount - ((realPosition - firstPositionInGroup) % spanCount);
        }
        try {
            nextGroupName = getGroupName(realPosition + findCount);
        } catch (Exception e) {
            nextGroupName = curGroupName;
        }
        if (nextGroupName == null) {
            return true;
        }
        return true ^ TextUtils.equals(curGroupName, nextGroupName);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDrawOver(Canvas c, RecyclerView parent, RecyclerView.State state) {
        super.onDrawOver(c, parent, state);
        if (this.gestureDetector == null) {
            this.gestureDetector = new GestureDetector(parent.getContext(), this.gestureListener);
            parent.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.decoration.BaseDecoration.2
                @Override // android.view.View.OnTouchListener
                public boolean onTouch(View v, MotionEvent event) {
                    return BaseDecoration.this.gestureDetector.onTouchEvent(event);
                }
            });
        }
        this.stickyHeaderPosArray.clear();
    }

    private void onGroupClick(int realPosition, int viewId) {
        OnGroupClickListener onGroupClickListener = this.mOnGroupClickListener;
        if (onGroupClickListener != null) {
            onGroupClickListener.onClick(realPosition, viewId);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onTouchEvent(MotionEvent e) {
        for (Map.Entry<Integer, ClickInfo> entry : this.stickyHeaderPosArray.entrySet()) {
            ClickInfo value = this.stickyHeaderPosArray.get(entry.getKey());
            float y = e.getY();
            float x = e.getX();
            if (value.mBottom - this.mGroupHeight <= y && y <= value.mBottom) {
                if (value.mDetailInfoList == null || value.mDetailInfoList.size() == 0) {
                    onGroupClick(entry.getKey().intValue(), value.mGroupId);
                    return true;
                }
                List<ClickInfo.DetailInfo> list = value.mDetailInfoList;
                boolean isChildViewClicked = false;
                Iterator<ClickInfo.DetailInfo> it = list.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    ClickInfo.DetailInfo detailInfo = it.next();
                    if (detailInfo.top <= y && y <= detailInfo.bottom && detailInfo.left <= x && detailInfo.right >= x) {
                        onGroupClick(entry.getKey().intValue(), detailInfo.id);
                        isChildViewClicked = true;
                        break;
                    }
                }
                if (!isChildViewClicked) {
                    onGroupClick(entry.getKey().intValue(), value.mGroupId);
                    return true;
                }
                return true;
            }
        }
        return false;
    }

    protected void drawDivide(Canvas c, RecyclerView parent, View childView, int realPosition, int left, int right) {
        if (this.mDivideHeight != 0 && !isHeader(realPosition)) {
            RecyclerView.LayoutManager manager = parent.getLayoutManager();
            if (manager instanceof GridLayoutManager) {
                int spanCount = ((GridLayoutManager) manager).getSpanCount();
                if (!isFirstLineInGroup(realPosition, spanCount)) {
                    float bottom = childView.getTop() + parent.getPaddingTop();
                    if (bottom >= this.mGroupHeight) {
                        c.drawRect(left, bottom - this.mDivideHeight, right, bottom, this.mDividePaint);
                        return;
                    }
                    return;
                }
                return;
            }
            float bottom2 = childView.getTop();
            if (bottom2 >= this.mGroupHeight) {
                c.drawRect(left, bottom2 - this.mDivideHeight, right, bottom2, this.mDividePaint);
            }
        }
    }

    protected void log(String content) {
    }
}
