package im.uwrkaxlmjj.ui.hui.decoration;

import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;

/* JADX INFO: loaded from: classes5.dex */
public class DefaultItemDecoration extends BaseItemDecoration<DefaultItemDecoration> {
    private Drawable mDivider;
    private int mDividerHeight;
    private int mDividerWidth;
    private boolean mDrawFirst;
    private boolean mDrawLast;

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
        int position = parent.getChildAdapterPosition(view);
        if (position < 0) {
            return;
        }
        if (this.mExcludeViewTypeList.contains(Integer.valueOf(parent.getAdapter().getItemViewType(position)))) {
            outRect.set(0, 0, 0, 0);
            return;
        }
        int columnCount = getSpanCount(parent);
        int childCount = parent.getAdapter().getItemCount();
        boolean firstRow = isFirstRow(position, columnCount);
        boolean lastRow = isLastRow(position, columnCount, childCount);
        boolean firstColumn = isFirstColumn(position, columnCount);
        boolean lastColumn = isLastColumn(position, columnCount);
        boolean isHorizontal = isHorizontal(parent);
        if (columnCount == 1) {
            if (firstRow) {
                if (this.mDrawFirst) {
                    if (isHorizontal) {
                        int i = this.mDividerWidth;
                        outRect.set(i, 0, i / 2, 0);
                        return;
                    } else {
                        int i2 = this.mDividerHeight;
                        outRect.set(0, i2, 0, i2 / 2);
                        return;
                    }
                }
                if (isHorizontal) {
                    outRect.set(0, 0, this.mDividerWidth / 2, 0);
                    return;
                } else {
                    outRect.set(0, 0, 0, this.mDividerHeight / 2);
                    return;
                }
            }
            if (lastRow) {
                if (this.mDrawLast) {
                    if (isHorizontal) {
                        int i3 = this.mDividerWidth;
                        outRect.set(i3 / 2, 0, i3, 0);
                        return;
                    } else {
                        int i4 = this.mDividerHeight;
                        outRect.set(0, i4 / 2, 0, i4);
                        return;
                    }
                }
                if (isHorizontal) {
                    outRect.set(this.mDividerWidth / 2, 0, 0, 0);
                    return;
                } else {
                    outRect.set(0, this.mDividerHeight / 2, 0, 0);
                    return;
                }
            }
            if (isHorizontal) {
                int i5 = this.mDividerWidth;
                outRect.set(i5 / 2, 0, i5 / 2, 0);
                return;
            } else {
                int i6 = this.mDividerHeight;
                outRect.set(0, i6 / 2, 0, i6 / 2);
                return;
            }
        }
        if (firstRow && firstColumn) {
            outRect.set(0, 0, this.mDividerWidth / 2, this.mDividerHeight / 2);
            return;
        }
        if (firstRow && lastColumn) {
            outRect.set(this.mDividerWidth / 2, 0, 0, this.mDividerHeight / 2);
            return;
        }
        if (firstRow) {
            int i7 = this.mDividerWidth;
            outRect.set(i7 / 2, 0, i7 / 2, this.mDividerHeight / 2);
            return;
        }
        if (lastRow && firstColumn) {
            outRect.set(0, this.mDividerHeight / 2, this.mDividerWidth / 2, 0);
            return;
        }
        if (lastRow && lastColumn) {
            outRect.set(this.mDividerWidth / 2, this.mDividerHeight / 2, 0, 0);
            return;
        }
        if (lastRow) {
            int i8 = this.mDividerWidth;
            outRect.set(i8 / 2, this.mDividerHeight / 2, i8 / 2, 0);
            return;
        }
        if (firstColumn) {
            int i9 = this.mDividerHeight;
            outRect.set(0, i9 / 2, this.mDividerWidth / 2, i9 / 2);
        } else if (lastColumn) {
            int i10 = this.mDividerWidth / 2;
            int i11 = this.mDividerHeight;
            outRect.set(i10, i11 / 2, 0, i11 / 2);
        } else {
            int i12 = this.mDividerWidth;
            int i13 = this.mDividerHeight;
            outRect.set(i12 / 2, i13 / 2, i12 / 2, i13 / 2);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDraw(Canvas c, RecyclerView parent, RecyclerView.State state) {
        drawHorizontal(c, parent);
        drawVertical(c, parent);
    }

    public void drawHorizontal(Canvas c, RecyclerView parent) {
        c.save();
        int childCount = parent.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = parent.getChildAt(i);
            int childPosition = parent.getChildAdapterPosition(child);
            if (childPosition >= 0 && !this.mExcludeViewTypeList.contains(Integer.valueOf(parent.getAdapter().getItemViewType(childPosition)))) {
                int left = child.getLeft();
                int top = child.getBottom();
                int right = child.getRight();
                int bottom = this.mDividerHeight + top;
                this.mDivider.setBounds(left, top, right, bottom);
                this.mDivider.draw(c);
            }
        }
        c.restore();
    }

    public void drawVertical(Canvas c, RecyclerView parent) {
        c.save();
        int childCount = parent.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = parent.getChildAt(i);
            int childPosition = parent.getChildAdapterPosition(child);
            if (childPosition >= 0 && !this.mExcludeViewTypeList.contains(Integer.valueOf(parent.getAdapter().getItemViewType(childPosition)))) {
                int left = child.getRight();
                int top = child.getTop();
                int right = this.mDividerWidth + left;
                int bottom = child.getBottom();
                this.mDivider.setBounds(left, top, right, bottom);
                this.mDivider.draw(c);
            }
        }
        c.restore();
    }

    public DefaultItemDecoration setDividerHeight(int dividerHeight) {
        this.mDividerHeight = dividerHeight;
        return this;
    }

    public DefaultItemDecoration setDividerWidth(int dividerWidth) {
        this.mDividerWidth = dividerWidth;
        return this;
    }

    public DefaultItemDecoration setDividerColor(int dividerColor) {
        return setDivider(new ColorDrawable(dividerColor));
    }

    public DefaultItemDecoration setDivider(Drawable divider) {
        this.mDivider = divider;
        return this;
    }

    public DefaultItemDecoration setDrawFirst(boolean drawFirst) {
        this.mDrawFirst = drawFirst;
        return this;
    }

    public DefaultItemDecoration setDrawLast(boolean drawLast) {
        this.mDrawLast = drawLast;
        return this;
    }
}
