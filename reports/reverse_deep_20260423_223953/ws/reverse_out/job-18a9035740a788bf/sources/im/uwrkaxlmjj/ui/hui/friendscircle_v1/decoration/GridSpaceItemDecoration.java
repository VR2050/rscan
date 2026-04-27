package im.uwrkaxlmjj.ui.hui.friendscircle_v1.decoration;

import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;

/* JADX INFO: loaded from: classes5.dex */
public class GridSpaceItemDecoration extends RecyclerView.ItemDecoration {
    private boolean mBorderVisible;
    private int mHorizontalSpacing;
    private int mVerticalSpacing;

    public static class Param {
        public boolean borderVisible;
        public int margin;
        public int marginHorizontal;
        public int marginVertical;
    }

    public GridSpaceItemDecoration() {
    }

    public GridSpaceItemDecoration(int spacing, boolean borderVisible) {
        this.mHorizontalSpacing = spacing;
        this.mVerticalSpacing = spacing;
        this.mBorderVisible = borderVisible;
    }

    public GridSpaceItemDecoration(int horizontalSpacing, int verticalSpacing, boolean borderVisible) {
        this.mHorizontalSpacing = horizontalSpacing;
        this.mVerticalSpacing = verticalSpacing;
        this.mBorderVisible = borderVisible;
    }

    public GridSpaceItemDecoration(int spacing) {
        this.mHorizontalSpacing = spacing;
        this.mVerticalSpacing = spacing;
    }

    public GridSpaceItemDecoration(int horizontalSpacing, int verticalSpacing) {
        this.mHorizontalSpacing = horizontalSpacing;
        this.mVerticalSpacing = verticalSpacing;
    }

    public void setParams(Param params) {
        if (params.margin > 0) {
            this.mHorizontalSpacing = params.margin;
            this.mVerticalSpacing = params.margin;
        } else {
            this.mHorizontalSpacing = params.marginHorizontal;
            this.mVerticalSpacing = params.marginVertical;
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
        if (parent.getChildCount() == 0) {
            return;
        }
        if (parent.getLayoutManager() instanceof GridLayoutManager) {
            GridLayoutManager layoutManager = (GridLayoutManager) parent.getLayoutManager();
            if (layoutManager.getOrientation() == 0) {
                try {
                    throw new IllegalAccessException("RecyclerViewGridSpaceItemDecoration only support GridLayoutManager/StaggeredGridLayoutManager Vertical");
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                    return;
                }
            } else {
                int position = parent.getChildAdapterPosition(view);
                int spanCount = layoutManager.getSpanCount();
                GridLayoutManager.LayoutParams lp = (GridLayoutManager.LayoutParams) view.getLayoutParams();
                int column = lp.getSpanIndex();
                getGridItemOffsets(outRect, position, column, spanCount);
                return;
            }
        }
        if (parent.getLayoutManager() instanceof StaggeredGridLayoutManager) {
            StaggeredGridLayoutManager layoutManager2 = (StaggeredGridLayoutManager) parent.getLayoutManager();
            if (layoutManager2.getOrientation() == 0) {
                try {
                    throw new IllegalAccessException("RecyclerViewGridSpaceItemDecoration only support GridLayoutManager/StaggeredGridLayoutManager Vertical");
                } catch (IllegalAccessException e2) {
                    e2.printStackTrace();
                    return;
                }
            } else {
                int position2 = parent.getChildAdapterPosition(view);
                int spanCount2 = layoutManager2.getSpanCount();
                StaggeredGridLayoutManager.LayoutParams lp2 = (StaggeredGridLayoutManager.LayoutParams) view.getLayoutParams();
                int column2 = lp2.getSpanIndex();
                getGridItemOffsets(outRect, position2, column2, spanCount2);
                return;
            }
        }
        try {
            throw new IllegalAccessException("RecyclerViewGridSpaceItemDecoration only support GridLayoutManager/StaggeredGridLayoutManager");
        } catch (IllegalAccessException e3) {
            e3.printStackTrace();
        }
    }

    private void getGridItemOffsets(Rect outRect, int position, int column, int spanCount) {
        if (this.mBorderVisible) {
            outRect.left = (this.mHorizontalSpacing * (spanCount - column)) / spanCount;
            outRect.right = (this.mHorizontalSpacing * (column + 1)) / spanCount;
            if (position < spanCount) {
                outRect.top = this.mVerticalSpacing;
            }
            outRect.bottom = this.mVerticalSpacing;
            return;
        }
        outRect.left = (this.mHorizontalSpacing * column) / spanCount;
        outRect.right = (this.mHorizontalSpacing * ((spanCount - 1) - column)) / spanCount;
        if (position >= spanCount) {
            outRect.top = this.mVerticalSpacing;
        }
    }
}
