package com.jbzd.media.movecartoons.view.flow;

import android.graphics.Rect;
import android.util.SparseArray;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class FlowLayoutManager extends RecyclerView.LayoutManager {
    private static final String TAG = "FlowLayoutManager";
    public int height;
    private int left;
    private int right;
    private int top;
    private int usedMaxWidth;
    public int width;
    public final FlowLayoutManager self = this;
    private int verticalScrollOffset = 0;
    public int totalHeight = 0;
    private Row row = new Row();
    private List<Row> lineRows = new ArrayList();
    private SparseArray<Rect> allItemFrames = new SparseArray<>();

    public class Item {
        public Rect rect;
        public int useHeight;
        public View view;

        public Item(int i2, View view, Rect rect) {
            this.useHeight = i2;
            this.view = view;
            this.rect = rect;
        }

        public void setRect(Rect rect) {
            this.rect = rect;
        }
    }

    public class Row {
        public float cuTop;
        public float maxHeight;
        public List<Item> views = new ArrayList();

        public Row() {
        }

        public void addViews(Item item) {
            this.views.add(item);
        }

        public void setCuTop(float f2) {
            this.cuTop = f2;
        }

        public void setMaxHeight(float f2) {
            this.maxHeight = f2;
        }
    }

    public FlowLayoutManager() {
        setAutoMeasureEnabled(true);
    }

    private void fillLayout(RecyclerView.Recycler recycler, RecyclerView.State state) {
        if (state.isPreLayout() || getItemCount() == 0) {
            return;
        }
        new Rect(getPaddingLeft(), getPaddingTop() + this.verticalScrollOffset, getWidth() - getPaddingRight(), (getHeight() - getPaddingBottom()) + this.verticalScrollOffset);
        for (int i2 = 0; i2 < this.lineRows.size(); i2++) {
            Row row = this.lineRows.get(i2);
            float f2 = row.cuTop;
            List<Item> list = row.views;
            for (int i3 = 0; i3 < list.size(); i3++) {
                View view = list.get(i3).view;
                measureChildWithMargins(view, 0, 0);
                addView(view);
                Rect rect = list.get(i3).rect;
                int i4 = rect.left;
                int i5 = rect.top;
                int i6 = this.verticalScrollOffset;
                layoutDecoratedWithMargins(view, i4, i5 - i6, rect.right, rect.bottom - i6);
            }
        }
    }

    private void formatAboveRow() {
        List<Item> list = this.row.views;
        for (int i2 = 0; i2 < list.size(); i2++) {
            Item item = list.get(i2);
            int position = getPosition(item.view);
            float f2 = this.allItemFrames.get(position).top;
            Row row = this.row;
            if (f2 < ((row.maxHeight - list.get(i2).useHeight) / 2.0f) + row.cuTop) {
                Rect rect = this.allItemFrames.get(position);
                if (rect == null) {
                    rect = new Rect();
                }
                int i3 = this.allItemFrames.get(position).left;
                Row row2 = this.row;
                int i4 = (int) (((row2.maxHeight - list.get(i2).useHeight) / 2.0f) + row2.cuTop);
                int i5 = this.allItemFrames.get(position).right;
                Row row3 = this.row;
                rect.set(i3, i4, i5, (int) (((row3.maxHeight - list.get(i2).useHeight) / 2.0f) + row3.cuTop + getDecoratedMeasuredHeight(r3)));
                this.allItemFrames.put(position, rect);
                item.setRect(rect);
                list.set(i2, item);
            }
        }
        Row row4 = this.row;
        row4.views = list;
        this.lineRows.add(row4);
        this.row = new Row();
    }

    private int getVerticalSpace() {
        return (this.self.getHeight() - this.self.getPaddingBottom()) - this.self.getPaddingTop();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollVertically() {
        return true;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public RecyclerView.LayoutParams generateDefaultLayoutParams() {
        return new RecyclerView.LayoutParams(-2, -2);
    }

    public int getHorizontalSpace() {
        return (this.self.getWidth() - this.self.getPaddingLeft()) - this.self.getPaddingRight();
    }

    public int getTotalHeight() {
        return this.totalHeight;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onLayoutChildren(RecyclerView.Recycler recycler, RecyclerView.State state) {
        this.totalHeight = 0;
        int i2 = this.top;
        this.row = new Row();
        this.lineRows.clear();
        this.allItemFrames.clear();
        removeAllViews();
        if (getItemCount() == 0) {
            detachAndScrapAttachedViews(recycler);
            this.verticalScrollOffset = 0;
            return;
        }
        if (getChildCount() == 0 && state.isPreLayout()) {
            return;
        }
        detachAndScrapAttachedViews(recycler);
        if (getChildCount() == 0) {
            this.width = getWidth();
            this.height = getHeight();
            this.left = getPaddingLeft();
            this.right = getPaddingRight();
            this.top = getPaddingTop();
            this.usedMaxWidth = (this.width - this.left) - this.right;
        }
        int i3 = 0;
        int i4 = 0;
        for (int i5 = 0; i5 < getItemCount(); i5++) {
            View viewForPosition = recycler.getViewForPosition(i5);
            if (8 != viewForPosition.getVisibility()) {
                measureChildWithMargins(viewForPosition, 0, 0);
                int decoratedMeasuredWidth = getDecoratedMeasuredWidth(viewForPosition);
                int decoratedMeasuredHeight = getDecoratedMeasuredHeight(viewForPosition);
                int i6 = i3 + decoratedMeasuredWidth;
                if (i6 <= this.usedMaxWidth) {
                    int i7 = this.left + i3;
                    Rect rect = this.allItemFrames.get(i5);
                    if (rect == null) {
                        rect = new Rect();
                    }
                    rect.set(i7, i2, decoratedMeasuredWidth + i7, i2 + decoratedMeasuredHeight);
                    this.allItemFrames.put(i5, rect);
                    i4 = Math.max(i4, decoratedMeasuredHeight);
                    this.row.addViews(new Item(decoratedMeasuredHeight, viewForPosition, rect));
                    this.row.setCuTop(i2);
                    this.row.setMaxHeight(i4);
                    i3 = i6;
                } else {
                    formatAboveRow();
                    i2 += i4;
                    this.totalHeight += i4;
                    int i8 = this.left;
                    Rect rect2 = this.allItemFrames.get(i5);
                    if (rect2 == null) {
                        rect2 = new Rect();
                    }
                    rect2.set(i8, i2, i8 + decoratedMeasuredWidth, i2 + decoratedMeasuredHeight);
                    this.allItemFrames.put(i5, rect2);
                    this.row.addViews(new Item(decoratedMeasuredHeight, viewForPosition, rect2));
                    this.row.setCuTop(i2);
                    this.row.setMaxHeight(decoratedMeasuredHeight);
                    i3 = decoratedMeasuredWidth;
                    i4 = decoratedMeasuredHeight;
                }
                if (i5 == getItemCount() - 1) {
                    formatAboveRow();
                    this.totalHeight += i4;
                }
            }
        }
        this.totalHeight = Math.max(this.totalHeight, getVerticalSpace());
        fillLayout(recycler, state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollVerticallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        int i3 = this.verticalScrollOffset;
        if (i3 + i2 < 0) {
            i2 = -i3;
        } else if (i3 + i2 > this.totalHeight - getVerticalSpace()) {
            i2 = (this.totalHeight - getVerticalSpace()) - this.verticalScrollOffset;
        }
        this.verticalScrollOffset += i2;
        offsetChildrenVertical(-i2);
        fillLayout(recycler, state);
        return i2;
    }
}
