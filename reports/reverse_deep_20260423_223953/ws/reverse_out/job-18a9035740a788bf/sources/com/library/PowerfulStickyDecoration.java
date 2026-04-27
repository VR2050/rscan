package com.library;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.library.ClickInfo;
import com.library.cache.CacheUtil;
import com.library.listener.OnGroupClickListener;
import com.library.listener.PowerGroupListener;
import com.library.util.ViewUtil;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public class PowerfulStickyDecoration extends BaseDecoration {
    private CacheUtil<Bitmap> mBitmapCache;
    private PowerGroupListener mGroupListener;
    private Paint mGroutPaint;
    private CacheUtil<View> mHeadViewCache;

    private PowerfulStickyDecoration(PowerGroupListener groupListener) {
        this.mBitmapCache = new CacheUtil<>();
        this.mHeadViewCache = new CacheUtil<>();
        this.mGroupListener = groupListener;
        this.mGroutPaint = new Paint();
    }

    @Override // com.library.BaseDecoration, androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDrawOver(Canvas c, RecyclerView parent, RecyclerView.State state) {
        int childCount;
        int bottom;
        super.onDrawOver(c, parent, state);
        int itemCount = state.getItemCount();
        int childCount2 = parent.getChildCount();
        int left = parent.getPaddingLeft();
        int right = parent.getWidth() - parent.getPaddingRight();
        int i = 0;
        while (i < childCount2) {
            View childView = parent.getChildAt(i);
            int position = parent.getChildAdapterPosition(childView);
            int realPosition = getRealPosition(position);
            if (isFirstInGroup(realPosition) || isFirstInRecyclerView(realPosition, i)) {
                childCount = childCount2;
                int childCount3 = realPosition;
                int viewBottom = childView.getBottom();
                int bottom2 = Math.max(this.mGroupHeight, childView.getTop() + parent.getPaddingTop());
                if (position + 1 < itemCount && isLastLineInGroup(parent, childCount3) && viewBottom < bottom2) {
                    bottom = viewBottom;
                } else {
                    bottom = bottom2;
                }
                drawDecoration(c, childCount3, left, right, bottom);
                i++;
                childCount2 = childCount;
            } else {
                childCount = childCount2;
                drawDivide(c, parent, childView, realPosition, left, right);
                i++;
                childCount2 = childCount;
            }
        }
    }

    private void drawDecoration(Canvas c, int realPosition, int left, int right, int bottom) {
        View groupView;
        Bitmap bitmap;
        c.drawRect(left, bottom - this.mGroupHeight, right, bottom, this.mGroutPaint);
        int firstPositionInGroup = getFirstInGroupWithCash(realPosition);
        if (this.mHeadViewCache.get(firstPositionInGroup) == null) {
            groupView = getGroupView(firstPositionInGroup);
            if (groupView == null) {
                return;
            }
            measureAndLayoutView(groupView, left, right);
            this.mHeadViewCache.put(firstPositionInGroup, groupView);
        } else {
            groupView = this.mHeadViewCache.get(firstPositionInGroup);
        }
        if (this.mBitmapCache.get(firstPositionInGroup) != null) {
            bitmap = this.mBitmapCache.get(firstPositionInGroup);
        } else {
            bitmap = Bitmap.createBitmap(groupView.getDrawingCache());
            this.mBitmapCache.put(firstPositionInGroup, bitmap);
        }
        c.drawBitmap(bitmap, left, bottom - this.mGroupHeight, (Paint) null);
        if (this.mOnGroupClickListener != null) {
            setClickInfo(groupView, left, bottom, realPosition);
        }
    }

    private void measureAndLayoutView(View groupView, int left, int right) {
        groupView.setDrawingCacheEnabled(true);
        ViewGroup.LayoutParams layoutParams = new ViewGroup.LayoutParams(right, this.mGroupHeight);
        groupView.setLayoutParams(layoutParams);
        groupView.measure(View.MeasureSpec.makeMeasureSpec(right, 1073741824), View.MeasureSpec.makeMeasureSpec(this.mGroupHeight, 1073741824));
        groupView.layout(left, 0 - this.mGroupHeight, right, 0);
    }

    private void setClickInfo(View groupView, int parentLeft, int parentBottom, int realPosition) {
        int parentTop = parentBottom - this.mGroupHeight;
        List<ClickInfo.DetailInfo> list = new ArrayList<>();
        List<View> viewList = ViewUtil.getChildViewWithId(groupView);
        for (View view : viewList) {
            int top = view.getTop() + parentTop;
            int bottom = view.getBottom() + parentTop;
            int left = view.getLeft() + parentLeft;
            int right = view.getRight() + parentLeft;
            list.add(new ClickInfo.DetailInfo(view.getId(), left, right, top, bottom));
            parentTop = parentTop;
        }
        ClickInfo clickInfo = new ClickInfo(parentBottom, list);
        clickInfo.mGroupId = groupView.getId();
        this.stickyHeaderPosArray.put(Integer.valueOf(realPosition), clickInfo);
    }

    @Override // com.library.BaseDecoration
    String getGroupName(int realPosition) {
        PowerGroupListener powerGroupListener = this.mGroupListener;
        if (powerGroupListener != null) {
            return powerGroupListener.getGroupName(realPosition);
        }
        return null;
    }

    private View getGroupView(int realPosition) {
        PowerGroupListener powerGroupListener = this.mGroupListener;
        if (powerGroupListener != null) {
            return powerGroupListener.getGroupView(realPosition);
        }
        return null;
    }

    public void setCacheEnable(boolean b) {
        this.mHeadViewCache.isCacheable(b);
    }

    public void clearCache() {
        this.mHeadViewCache.clean();
        this.mBitmapCache.clean();
    }

    public void notifyRedraw(RecyclerView recyclerView, View viewGroup, int realPosition) {
        viewGroup.setDrawingCacheEnabled(false);
        int firstPositionInGroup = getFirstInGroupWithCash(realPosition);
        this.mBitmapCache.remove(firstPositionInGroup);
        this.mHeadViewCache.remove(firstPositionInGroup);
        int left = recyclerView.getPaddingLeft();
        int right = recyclerView.getWidth() - recyclerView.getPaddingRight();
        measureAndLayoutView(viewGroup, left, right);
        this.mHeadViewCache.put(firstPositionInGroup, viewGroup);
        recyclerView.invalidate();
    }

    public static class Builder {
        PowerfulStickyDecoration mDecoration;

        private Builder(PowerGroupListener listener) {
            this.mDecoration = new PowerfulStickyDecoration(listener);
        }

        public static Builder init(PowerGroupListener listener) {
            return new Builder(listener);
        }

        public Builder setGroupHeight(int groutHeight) {
            this.mDecoration.mGroupHeight = groutHeight;
            return this;
        }

        public Builder setGroupBackground(int background) {
            this.mDecoration.mGroupBackground = background;
            this.mDecoration.mGroutPaint.setColor(this.mDecoration.mGroupBackground);
            return this;
        }

        public Builder setDivideHeight(int height) {
            this.mDecoration.mDivideHeight = height;
            return this;
        }

        public Builder setDivideColor(int color) {
            this.mDecoration.mDivideColor = color;
            this.mDecoration.mDividePaint.setColor(this.mDecoration.mDivideColor);
            return this;
        }

        public Builder setOnClickListener(OnGroupClickListener listener) {
            this.mDecoration.setOnGroupClickListener(listener);
            return this;
        }

        public Builder resetSpan(RecyclerView recyclerView, GridLayoutManager gridLayoutManager) {
            this.mDecoration.resetSpan(recyclerView, gridLayoutManager);
            return this;
        }

        public Builder setCacheEnable(boolean b) {
            this.mDecoration.setCacheEnable(b);
            return this;
        }

        public Builder setHeaderCount(int headerCount) {
            if (headerCount >= 0) {
                this.mDecoration.mHeaderCount = headerCount;
            }
            return this;
        }

        public PowerfulStickyDecoration build() {
            return this.mDecoration;
        }
    }
}
