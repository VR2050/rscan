package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.text.TextUtilsCompat;
import im.uwrkaxlmjj.messenger.R;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/* JADX INFO: loaded from: classes5.dex */
public class FlowLayout extends ViewGroup {
    private static final int CENTER = 0;
    private static final int LEFT = -1;
    private static final int RIGHT = 1;
    private static final String TAG = "FlowLayout";
    private List<View> lineViews;
    protected List<List<View>> mAllViews;
    private int mGravity;
    protected List<Integer> mLineHeight;
    protected List<Integer> mLineWidth;

    public FlowLayout(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        this.mAllViews = new ArrayList();
        this.mLineHeight = new ArrayList();
        this.mLineWidth = new ArrayList();
        this.lineViews = new ArrayList();
        TypedArray ta = context.obtainStyledAttributes(attrs, R.styleable.TagFlowLayout);
        this.mGravity = ta.getInt(1, -1);
        int layoutDirection = TextUtilsCompat.getLayoutDirectionFromLocale(Locale.getDefault());
        if (layoutDirection == 1) {
            if (this.mGravity == -1) {
                this.mGravity = 1;
            } else {
                this.mGravity = -1;
            }
        }
        ta.recycle();
    }

    public FlowLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public FlowLayout(Context context) {
        this(context, null);
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int sizeHeight;
        int sizeWidth;
        int lineWidth;
        int lineHeight;
        int sizeWidth2 = View.MeasureSpec.getSize(widthMeasureSpec);
        int modeWidth = View.MeasureSpec.getMode(widthMeasureSpec);
        int sizeHeight2 = View.MeasureSpec.getSize(heightMeasureSpec);
        int modeHeight = View.MeasureSpec.getMode(heightMeasureSpec);
        int width = 0;
        int height = 0;
        int lineWidth2 = 0;
        int lineHeight2 = 0;
        int cCount = getChildCount();
        int i = 0;
        while (i < cCount) {
            View child = getChildAt(i);
            if (child.getVisibility() != 8) {
                measureChild(child, widthMeasureSpec, heightMeasureSpec);
                ViewGroup.MarginLayoutParams lp = (ViewGroup.MarginLayoutParams) child.getLayoutParams();
                int measuredWidth = child.getMeasuredWidth();
                sizeHeight = sizeHeight2;
                int sizeHeight3 = lp.leftMargin;
                int childWidth = measuredWidth + sizeHeight3 + lp.rightMargin;
                int childHeight = child.getMeasuredHeight() + lp.topMargin + lp.bottomMargin;
                sizeWidth = sizeWidth2;
                if (lineWidth2 + childWidth > (sizeWidth2 - getPaddingLeft()) - getPaddingRight()) {
                    width = Math.max(width, lineWidth2);
                    lineWidth = childWidth;
                    height += lineHeight2;
                    lineHeight = childHeight;
                } else {
                    lineWidth = lineWidth2 + childWidth;
                    lineHeight = Math.max(lineHeight2, childHeight);
                }
                int lineHeight3 = cCount - 1;
                if (i != lineHeight3) {
                    lineHeight2 = lineHeight;
                    lineWidth2 = lineWidth;
                } else {
                    width = Math.max(lineWidth, width);
                    height += lineHeight;
                    lineHeight2 = lineHeight;
                    lineWidth2 = lineWidth;
                }
            } else if (i == cCount - 1) {
                width = Math.max(lineWidth2, width);
                height += lineHeight2;
                sizeWidth = sizeWidth2;
                sizeHeight = sizeHeight2;
            } else {
                sizeWidth = sizeWidth2;
                sizeHeight = sizeHeight2;
            }
            i++;
            sizeHeight2 = sizeHeight;
            sizeWidth2 = sizeWidth;
        }
        setMeasuredDimension(modeWidth == 1073741824 ? sizeWidth2 : getPaddingLeft() + width + getPaddingRight(), modeHeight == 1073741824 ? sizeHeight2 : getPaddingTop() + height + getPaddingBottom());
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
        int i;
        int lc;
        int tc;
        int width;
        FlowLayout flowLayout = this;
        flowLayout.mAllViews.clear();
        flowLayout.mLineHeight.clear();
        flowLayout.mLineWidth.clear();
        flowLayout.lineViews.clear();
        int width2 = getWidth();
        int lineWidth = 0;
        int lineHeight = 0;
        int cCount = getChildCount();
        int i2 = 0;
        while (true) {
            i = 8;
            if (i2 >= cCount) {
                break;
            }
            View child = flowLayout.getChildAt(i2);
            if (child.getVisibility() != 8) {
                ViewGroup.MarginLayoutParams lp = (ViewGroup.MarginLayoutParams) child.getLayoutParams();
                int childWidth = child.getMeasuredWidth();
                int childHeight = child.getMeasuredHeight();
                if (childWidth + lineWidth + lp.leftMargin + lp.rightMargin > (width2 - getPaddingLeft()) - getPaddingRight()) {
                    flowLayout.mLineHeight.add(Integer.valueOf(lineHeight));
                    flowLayout.mAllViews.add(flowLayout.lineViews);
                    flowLayout.mLineWidth.add(Integer.valueOf(lineWidth));
                    lineWidth = 0;
                    lineHeight = lp.topMargin + childHeight + lp.bottomMargin;
                    flowLayout.lineViews = new ArrayList();
                }
                lineWidth += lp.leftMargin + childWidth + lp.rightMargin;
                lineHeight = Math.max(lineHeight, lp.topMargin + childHeight + lp.bottomMargin);
                flowLayout.lineViews.add(child);
            }
            i2++;
        }
        flowLayout.mLineHeight.add(Integer.valueOf(lineHeight));
        flowLayout.mLineWidth.add(Integer.valueOf(lineWidth));
        flowLayout.mAllViews.add(flowLayout.lineViews);
        int left = getPaddingLeft();
        int top = getPaddingTop();
        int lineNum = flowLayout.mAllViews.size();
        int lastLayoutLineNum = -1;
        int i3 = 0;
        while (i3 < lineNum) {
            flowLayout.lineViews = flowLayout.mAllViews.get(i3);
            int lineHeight2 = flowLayout.mLineHeight.get(i3).intValue();
            int currentLineWidth = flowLayout.mLineWidth.get(i3).intValue();
            int i4 = flowLayout.mGravity;
            if (i4 == -1) {
                left = getPaddingLeft();
            } else if (i4 == 0) {
                left = ((width2 - currentLineWidth) / 2) + getPaddingLeft();
            } else if (i4 == 1) {
                left = (width2 - (getPaddingLeft() + currentLineWidth)) - getPaddingRight();
                Collections.reverse(flowLayout.lineViews);
            }
            int j = 0;
            while (j < flowLayout.lineViews.size()) {
                View child2 = flowLayout.lineViews.get(j);
                if (child2.getVisibility() == i) {
                    width = width2;
                } else {
                    ViewGroup.MarginLayoutParams lp2 = (ViewGroup.MarginLayoutParams) child2.getLayoutParams();
                    if (lastLayoutLineNum != i3) {
                        lc = left;
                    } else {
                        lc = left + lp2.leftMargin;
                    }
                    if (i3 == 0) {
                        tc = top;
                    } else {
                        tc = top + lp2.topMargin;
                    }
                    int rc = child2.getMeasuredWidth() + lc;
                    width = width2;
                    child2.layout(lc, tc, rc, tc + child2.getMeasuredHeight());
                    int measuredWidth = child2.getMeasuredWidth();
                    int rc2 = lp2.leftMargin;
                    left += measuredWidth + rc2 + lp2.rightMargin;
                }
                j++;
                i = 8;
                flowLayout = this;
                width2 = width;
            }
            int width3 = width2;
            top += lineHeight2;
            if (lastLayoutLineNum != i3) {
                lastLayoutLineNum = i3;
            }
            i3++;
            i = 8;
            flowLayout = this;
            width2 = width3;
        }
    }

    @Override // android.view.ViewGroup
    public ViewGroup.LayoutParams generateLayoutParams(AttributeSet attrs) {
        return new ViewGroup.MarginLayoutParams(getContext(), attrs);
    }

    @Override // android.view.ViewGroup
    protected ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return new ViewGroup.MarginLayoutParams(-2, -2);
    }

    @Override // android.view.ViewGroup
    protected ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams p) {
        return new ViewGroup.MarginLayoutParams(p);
    }
}
