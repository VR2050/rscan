package im.uwrkaxlmjj.ui.components.recyclerview.manager;

import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;

/* JADX INFO: loaded from: classes5.dex */
public class ExStaggeredGridLayoutManager extends StaggeredGridLayoutManager {
    private int[] dimension;
    private int[] measuredDimension;

    public ExStaggeredGridLayoutManager(int spanCount, int orientation) {
        super(spanCount, orientation);
        this.measuredDimension = new int[2];
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onMeasure(RecyclerView.Recycler recycler, RecyclerView.State state, int widthSpec, int heightSpec) {
        int width;
        int widthMode = View.MeasureSpec.getMode(widthSpec);
        int widthSize = View.MeasureSpec.getSize(widthSpec);
        int heightMode = View.MeasureSpec.getMode(heightSpec);
        int heightSize = View.MeasureSpec.getSize(heightSpec);
        int width2 = 0;
        int height = 0;
        int count = getItemCount();
        int span = getSpanCount();
        this.dimension = new int[span];
        int i = 0;
        while (i < count) {
            int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(i, 0);
            int width3 = View.MeasureSpec.makeMeasureSpec(i, 0);
            int width4 = width2;
            measureScrapChild(recycler, i, iMakeMeasureSpec, width3, this.measuredDimension);
            if (getOrientation() == 1) {
                int[] iArr = this.dimension;
                int iFindMinIndex = findMinIndex(iArr);
                iArr[iFindMinIndex] = iArr[iFindMinIndex] + this.measuredDimension[1];
            } else {
                int[] iArr2 = this.dimension;
                int iFindMinIndex2 = findMinIndex(iArr2);
                iArr2[iFindMinIndex2] = iArr2[iFindMinIndex2] + this.measuredDimension[0];
            }
            i++;
            width2 = width4;
        }
        int width5 = width2;
        if (getOrientation() == 1) {
            height = findMax(this.dimension);
            width = width5;
        } else {
            width = findMax(this.dimension);
        }
        if (widthMode == 1073741824) {
            width = widthSize;
        }
        if (heightMode == 1073741824) {
            height = heightSize;
        }
        setMeasuredDimension(width, height);
    }

    private void measureScrapChild(RecyclerView.Recycler recycler, int position, int widthSpec, int heightSpec, int[] measuredDimension) {
        if (position < getItemCount()) {
            try {
                View view = recycler.getViewForPosition(position);
                if (view != null) {
                    RecyclerView.LayoutParams lp = (RecyclerView.LayoutParams) view.getLayoutParams();
                    int childWidthSpec = ViewGroup.getChildMeasureSpec(widthSpec, getPaddingLeft() + getPaddingRight(), lp.width);
                    int childHeightSpec = ViewGroup.getChildMeasureSpec(heightSpec, getPaddingTop() + getPaddingBottom(), lp.height);
                    view.measure(childWidthSpec, childHeightSpec);
                    measuredDimension[0] = view.getMeasuredWidth() + lp.leftMargin + lp.rightMargin;
                    measuredDimension[1] = view.getMeasuredHeight() + lp.topMargin + lp.bottomMargin;
                    recycler.recycleView(view);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private int findMax(int[] array) {
        int max = array[0];
        for (int value : array) {
            if (value > max) {
                max = value;
            }
        }
        return max;
    }

    private int findMinIndex(int[] array) {
        int index = 0;
        int min = array[0];
        for (int i = 0; i < array.length; i++) {
            if (array[i] < min) {
                min = array[i];
                index = i;
            }
        }
        return index;
    }
}
