package com.lljjcoder.widget;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class RecycleViewDividerForList extends RecyclerView.ItemDecoration {
    private static final int[] ATTRS = {R.attr.listDivider};
    private Drawable mDivider;
    private int mDividerHeight;
    private boolean mLastLineShow;
    private int mOrientation;
    private Paint mPaint;

    public RecycleViewDividerForList(Context context, int i2) {
        this.mDividerHeight = 2;
        this.mLastLineShow = true;
        if (i2 != 1 && i2 != 0) {
            throw new IllegalArgumentException("请输入正确的参数！");
        }
        this.mOrientation = i2;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(ATTRS);
        this.mDivider = obtainStyledAttributes.getDrawable(0);
        obtainStyledAttributes.recycle();
    }

    private void drawHorizontal(Canvas canvas, RecyclerView recyclerView) {
        int paddingLeft = recyclerView.getPaddingLeft();
        int measuredWidth = recyclerView.getMeasuredWidth() - recyclerView.getPaddingRight();
        int childCount = recyclerView.getChildCount();
        for (int i2 = 0; i2 < childCount - (!this.mLastLineShow ? 1 : 0); i2++) {
            View childAt = recyclerView.getChildAt(i2);
            int bottom = childAt.getBottom() + ((ViewGroup.MarginLayoutParams) ((RecyclerView.LayoutParams) childAt.getLayoutParams())).bottomMargin;
            int i3 = this.mDividerHeight + bottom;
            Drawable drawable = this.mDivider;
            if (drawable != null) {
                drawable.setBounds(paddingLeft, bottom, measuredWidth, i3);
                this.mDivider.draw(canvas);
            }
            Paint paint = this.mPaint;
            if (paint != null) {
                canvas.drawRect(paddingLeft, bottom, measuredWidth, i3, paint);
            }
        }
    }

    private void drawVertical(Canvas canvas, RecyclerView recyclerView) {
        int paddingTop = recyclerView.getPaddingTop();
        int measuredHeight = recyclerView.getMeasuredHeight() - recyclerView.getPaddingBottom();
        int childCount = recyclerView.getChildCount();
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = recyclerView.getChildAt(i2);
            int right = childAt.getRight() + ((ViewGroup.MarginLayoutParams) ((RecyclerView.LayoutParams) childAt.getLayoutParams())).rightMargin;
            int i3 = this.mDividerHeight + right;
            Drawable drawable = this.mDivider;
            if (drawable != null) {
                drawable.setBounds(right, paddingTop, i3, measuredHeight);
                this.mDivider.draw(canvas);
            }
            Paint paint = this.mPaint;
            if (paint != null) {
                canvas.drawRect(right, paddingTop, i3, measuredHeight, paint);
            }
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect rect, View view, RecyclerView recyclerView, RecyclerView.State state) {
        super.getItemOffsets(rect, view, recyclerView, state);
        rect.set(0, 0, 0, this.mDividerHeight);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDraw(Canvas canvas, RecyclerView recyclerView, RecyclerView.State state) {
        super.onDraw(canvas, recyclerView, state);
        if (this.mOrientation == 1) {
            drawVertical(canvas, recyclerView);
        } else {
            drawHorizontal(canvas, recyclerView);
        }
    }

    public RecycleViewDividerForList(Context context, int i2, boolean z) {
        this.mDividerHeight = 2;
        this.mLastLineShow = true;
        if (i2 != 1 && i2 != 0) {
            throw new IllegalArgumentException("请输入正确的参数！");
        }
        this.mOrientation = i2;
        this.mLastLineShow = z;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(ATTRS);
        this.mDivider = obtainStyledAttributes.getDrawable(0);
        obtainStyledAttributes.recycle();
    }

    public RecycleViewDividerForList(Context context, int i2, int i3) {
        this(context, i2);
        Drawable drawable = ContextCompat.getDrawable(context, i3);
        this.mDivider = drawable;
        this.mDividerHeight = drawable.getIntrinsicHeight();
    }

    public RecycleViewDividerForList(Context context, int i2, int i3, int i4) {
        this(context, i2);
        this.mDividerHeight = i3;
        Paint paint = new Paint(1);
        this.mPaint = paint;
        paint.setColor(i4);
        this.mPaint.setStyle(Paint.Style.FILL);
    }
}
