package im.uwrkaxlmjj.ui.decoration;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.text.TextPaint;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.ui.decoration.listener.GroupListener;
import im.uwrkaxlmjj.ui.decoration.listener.OnGroupClickListener;

/* JADX INFO: loaded from: classes5.dex */
public class StickyDecoration extends BaseDecoration {
    private GroupListener mGroupListener;
    private int mGroupTextColor;
    private Paint mGroutPaint;
    private int mSideMargin;
    private TextPaint mTextPaint;
    private int mTextSize;
    private Typeface mTextTypeface;

    private StickyDecoration(GroupListener groupListener) {
        this.mGroupTextColor = -1;
        this.mSideMargin = 10;
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

    /* JADX WARN: Removed duplicated region for block: B:16:0x0061  */
    @Override // im.uwrkaxlmjj.ui.decoration.BaseDecoration, androidx.recyclerview.widget.RecyclerView.ItemDecoration
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
            if (r13 >= r10) goto L98
            android.view.View r14 = r8.getChildAt(r13)
            int r15 = r8.getChildAdapterPosition(r14)
            int r6 = r7.getRealPosition(r15)
            boolean r0 = r7.isOffset(r6)
            if (r0 != 0) goto L86
            boolean r0 = r7.isFirstInGroup(r6)
            if (r0 != 0) goto L3f
            boolean r0 = r7.isFirstInRecyclerView(r6, r13)
            if (r0 == 0) goto L86
        L3f:
            int r0 = r7.mGroupHeight
            int r1 = r14.getTop()
            int r2 = r19.getPaddingTop()
            int r1 = r1 + r2
            int r0 = java.lang.Math.max(r0, r1)
            int r1 = r15 + 1
            if (r1 >= r9) goto L61
            int r1 = r14.getBottom()
            boolean r2 = r7.isLastLineInGroup(r8, r6)
            if (r2 == 0) goto L61
            if (r1 >= r0) goto L61
            r0 = r1
            r5 = r0
            goto L62
        L61:
            r5 = r0
        L62:
            r0 = r17
            r1 = r18
            r2 = r6
            r3 = r11
            r4 = r12
            r16 = r5
            r0.drawDecoration(r1, r2, r3, r4, r5)
            im.uwrkaxlmjj.ui.decoration.listener.OnGroupClickListener r0 = r7.mOnGroupClickListener
            if (r0 == 0) goto L83
            java.util.HashMap<java.lang.Integer, im.uwrkaxlmjj.ui.decoration.ClickInfo> r0 = r7.stickyHeaderPosArray
            java.lang.Integer r1 = java.lang.Integer.valueOf(r6)
            im.uwrkaxlmjj.ui.decoration.ClickInfo r2 = new im.uwrkaxlmjj.ui.decoration.ClickInfo
            r3 = r16
            r2.<init>(r3)
            r0.put(r1, r2)
            goto L85
        L83:
            r3 = r16
        L85:
            goto L95
        L86:
            r0 = r17
            r1 = r18
            r2 = r19
            r3 = r14
            r4 = r6
            r5 = r11
            r16 = r6
            r6 = r12
            r0.drawDivide(r1, r2, r3, r4, r5, r6)
        L95:
            int r13 = r13 + 1
            goto L1f
        L98:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.decoration.StickyDecoration.onDrawOver(android.graphics.Canvas, androidx.recyclerview.widget.RecyclerView, androidx.recyclerview.widget.RecyclerView$State):void");
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

    @Override // im.uwrkaxlmjj.ui.decoration.BaseDecoration
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

        public Builder setGroupTextTypeface(Typeface textTypeface) {
            this.mDecoration.mTextTypeface = textTypeface;
            this.mDecoration.mGroutPaint.setTypeface(this.mDecoration.mTextTypeface);
            return this;
        }

        public Builder setGroupHeight(int groutHeight) {
            this.mDecoration.mGroupHeight = groutHeight;
            return this;
        }

        public Builder setOffset(int count) {
            this.mDecoration.setOffset(count);
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
