package com.library;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.text.TextPaint;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.library.listener.GroupListener;
import com.library.listener.OnGroupClickListener;

/* JADX INFO: loaded from: classes2.dex */
public class StickyDecoration extends BaseDecoration {
    private GroupListener mGroupListener;
    private int mGroupTextColor;
    private Paint mGroutPaint;
    private int mSideMargin;
    private TextPaint mTextPaint;
    private int mTextSize;

    private StickyDecoration(GroupListener groupListener) {
        this.mGroupTextColor = -1;
        this.mSideMargin = 0;
        this.mTextSize = 50;
        this.mGroupListener = groupListener;
        Paint paint = new Paint();
        this.mGroutPaint = paint;
        paint.setColor(this.mGroupBackground);
        TextPaint textPaint = new TextPaint();
        this.mTextPaint = textPaint;
        textPaint.setAntiAlias(true);
        this.mTextPaint.setTextSize(this.mTextSize);
        this.mTextPaint.setColor(this.mGroupTextColor);
        this.mTextPaint.setTextAlign(Paint.Align.LEFT);
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0073  */
    @Override // com.library.BaseDecoration, androidx.recyclerview.widget.RecyclerView.ItemDecoration
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onDrawOver(android.graphics.Canvas r18, androidx.recyclerview.widget.RecyclerView r19, androidx.recyclerview.widget.RecyclerView.State r20) {
        /*
            r17 = this;
            r7 = r17
            r8 = r19
            super.onDrawOver(r18, r19, r20)
            int r9 = r20.getItemCount()
            int r10 = r19.getChildCount()
            int r11 = r19.getPaddingLeft()
            int r0 = r19.getWidth()
            int r1 = r19.getPaddingRight()
            int r12 = r0 - r1
            r0 = 0
            r13 = r0
        L1f:
            if (r13 >= r10) goto L97
            android.view.View r14 = r8.getChildAt(r13)
            int r15 = r8.getChildAdapterPosition(r14)
            int r6 = r7.getRealPosition(r15)
            boolean r0 = r7.isFirstInGroup(r6)
            if (r0 != 0) goto L4e
            boolean r0 = r7.isFirstInRecyclerView(r6, r13)
            if (r0 == 0) goto L3d
            r16 = r10
            r10 = r6
            goto L51
        L3d:
            r0 = r17
            r1 = r18
            r2 = r19
            r3 = r14
            r4 = r6
            r5 = r11
            r16 = r10
            r10 = r6
            r6 = r12
            r0.drawDivide(r1, r2, r3, r4, r5, r6)
            goto L92
        L4e:
            r16 = r10
            r10 = r6
        L51:
            int r0 = r7.mGroupHeight
            int r1 = r14.getTop()
            int r2 = r19.getPaddingTop()
            int r1 = r1 + r2
            int r0 = java.lang.Math.max(r0, r1)
            int r1 = r15 + 1
            if (r1 >= r9) goto L73
            int r1 = r14.getBottom()
            boolean r2 = r7.isLastLineInGroup(r8, r10)
            if (r2 == 0) goto L73
            if (r1 >= r0) goto L73
            r0 = r1
            r6 = r0
            goto L74
        L73:
            r6 = r0
        L74:
            r0 = r17
            r1 = r18
            r2 = r10
            r3 = r11
            r4 = r12
            r5 = r6
            r0.drawDecoration(r1, r2, r3, r4, r5)
            com.library.listener.OnGroupClickListener r0 = r7.mOnGroupClickListener
            if (r0 == 0) goto L91
            java.util.HashMap<java.lang.Integer, com.library.ClickInfo> r0 = r7.stickyHeaderPosArray
            java.lang.Integer r1 = java.lang.Integer.valueOf(r10)
            com.library.ClickInfo r2 = new com.library.ClickInfo
            r2.<init>(r6)
            r0.put(r1, r2)
        L91:
        L92:
            int r13 = r13 + 1
            r10 = r16
            goto L1f
        L97:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.library.StickyDecoration.onDrawOver(android.graphics.Canvas, androidx.recyclerview.widget.RecyclerView, androidx.recyclerview.widget.RecyclerView$State):void");
    }

    private void drawDecoration(Canvas c, int realPosition, int left, int right, int bottom) {
        int firstPositionInGroup = getFirstInGroupWithCash(realPosition);
        String curGroupName = getGroupName(firstPositionInGroup);
        c.drawRect(left, bottom - this.mGroupHeight, right, bottom, this.mGroutPaint);
        if (curGroupName == null) {
            return;
        }
        Paint.FontMetrics fm = this.mTextPaint.getFontMetrics();
        float baseLine = (bottom - ((this.mGroupHeight - (fm.bottom - fm.top)) / 2.0f)) - fm.bottom;
        this.mSideMargin = Math.abs(this.mSideMargin);
        c.drawText(curGroupName, r4 + left, baseLine, this.mTextPaint);
    }

    @Override // com.library.BaseDecoration
    String getGroupName(int realPosition) {
        GroupListener groupListener = this.mGroupListener;
        if (groupListener != null) {
            return groupListener.getGroupName(realPosition);
        }
        return null;
    }

    public static class Builder {
        private StickyDecoration mDecoration;

        private Builder(GroupListener groupListener) {
            this.mDecoration = new StickyDecoration(groupListener);
        }

        public static Builder init(GroupListener groupListener) {
            return new Builder(groupListener);
        }

        public Builder setGroupBackground(int background) {
            this.mDecoration.mGroupBackground = background;
            this.mDecoration.mGroutPaint.setColor(this.mDecoration.mGroupBackground);
            return this;
        }

        public Builder setGroupTextSize(int textSize) {
            this.mDecoration.mTextSize = textSize;
            this.mDecoration.mTextPaint.setTextSize(this.mDecoration.mTextSize);
            return this;
        }

        public Builder setGroupHeight(int groutHeight) {
            this.mDecoration.mGroupHeight = groutHeight;
            return this;
        }

        public Builder setGroupTextColor(int color) {
            this.mDecoration.mGroupTextColor = color;
            this.mDecoration.mTextPaint.setColor(this.mDecoration.mGroupTextColor);
            return this;
        }

        public Builder setTextSideMargin(int leftMargin) {
            this.mDecoration.mSideMargin = leftMargin;
            return this;
        }

        public Builder setDivideHeight(int height) {
            this.mDecoration.mDivideHeight = height;
            return this;
        }

        public Builder setDivideColor(int color) {
            this.mDecoration.mDivideColor = color;
            this.mDecoration.mDividePaint.setColor(color);
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

        public Builder setHeaderCount(int headerCount) {
            if (headerCount >= 0) {
                this.mDecoration.mHeaderCount = headerCount;
            }
            return this;
        }

        public StickyDecoration build() {
            return this.mDecoration;
        }
    }
}
