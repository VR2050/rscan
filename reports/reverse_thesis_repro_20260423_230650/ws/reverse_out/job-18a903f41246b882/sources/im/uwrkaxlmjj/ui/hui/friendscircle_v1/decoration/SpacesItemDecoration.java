package im.uwrkaxlmjj.ui.hui.friendscircle_v1.decoration;

import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.ColorDrawable;
import android.view.View;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter;

/* JADX INFO: loaded from: classes5.dex */
public class SpacesItemDecoration extends RecyclerView.ItemDecoration {
    private boolean isShowBottom;
    private boolean isShowTop;
    private final Rect mBounds;
    private final ColorDrawable mDividerColorDrawable;
    private int space;

    public SpacesItemDecoration(int space) {
        this.mBounds = new Rect();
        this.mDividerColorDrawable = new ColorDrawable(Theme.getColor(Theme.key_windowBackgroundGray));
        this.space = space;
    }

    public SpacesItemDecoration(int space, int spaceColor) {
        this.mBounds = new Rect();
        this.mDividerColorDrawable = new ColorDrawable(spaceColor);
        this.space = space;
    }

    public SpacesItemDecoration isShowTop(boolean isShowTop) {
        this.isShowTop = isShowTop;
        return this;
    }

    public SpacesItemDecoration setShowBottom(boolean showBottom) {
        this.isShowBottom = showBottom;
        return this;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
        boolean isHorizontal;
        if (parent.getAdapter() != null) {
            RecyclerView.LayoutManager manager = parent.getLayoutManager();
            if (manager instanceof LinearLayoutManager) {
                isHorizontal = ((LinearLayoutManager) manager).getOrientation() == 0;
            } else {
                boolean isHorizontal2 = manager instanceof StaggeredGridLayoutManager;
                isHorizontal = isHorizontal2 && ((StaggeredGridLayoutManager) manager).getOrientation() == 0;
            }
            int position = parent.getChildAdapterPosition(view);
            if (position == 0 && this.isShowTop) {
                if (isHorizontal) {
                    outRect.right = this.space;
                    return;
                } else {
                    outRect.top = this.space;
                    outRect.bottom = this.space;
                    return;
                }
            }
            if (this.isShowBottom) {
                if (parent.getAdapter() instanceof PageSelectionAdapter) {
                    if (((PageSelectionAdapter) parent.getAdapter()).isShowLoadMoreViewEnable() && position == ((PageSelectionAdapter) parent.getAdapter()).getDataCount() - 1) {
                        if (isHorizontal) {
                            outRect.bottom = this.space;
                            return;
                        } else {
                            outRect.right = this.space;
                            return;
                        }
                    }
                    return;
                }
                if (parent.getAdapter().getItemCount() - 1 == position) {
                    if (isHorizontal) {
                        outRect.right = 0;
                        return;
                    } else {
                        outRect.bottom = 0;
                        return;
                    }
                }
                return;
            }
            if (isHorizontal) {
                outRect.right = this.space;
                return;
            } else {
                outRect.bottom = this.space;
                return;
            }
        }
        super.getItemOffsets(outRect, view, parent, state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDraw(Canvas c, RecyclerView parent, RecyclerView.State state) {
        if (parent.getLayoutManager() != null && this.mDividerColorDrawable != null) {
            drawVertical(c, parent);
        }
    }

    private void drawVertical(Canvas canvas, RecyclerView parent) {
        int left;
        int right;
        canvas.save();
        if (parent.getClipToPadding()) {
            left = parent.getPaddingLeft();
            right = parent.getWidth() - parent.getPaddingRight();
            canvas.clipRect(left, parent.getPaddingTop(), right, parent.getHeight() - parent.getPaddingBottom());
        } else {
            left = 0;
            right = parent.getWidth();
        }
        int childCount = parent.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = parent.getChildAt(i);
            parent.getDecoratedBoundsWithMargins(child, this.mBounds);
            int bottom = this.mBounds.bottom + Math.round(child.getTranslationY());
            int top = this.mBounds.top;
            this.mDividerColorDrawable.setBounds(left, top, right, bottom);
            this.mDividerColorDrawable.draw(canvas);
        }
        canvas.restore();
    }
}
