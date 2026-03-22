package com.lljjcoder.style.citypickerview.widget.wheel;

import android.view.View;
import android.widget.LinearLayout;
import java.util.LinkedList;
import java.util.List;

/* loaded from: classes2.dex */
public class WheelRecycle {
    private List<View> emptyItems;
    private List<View> items;
    private WheelView wheel;

    public WheelRecycle(WheelView wheelView) {
        this.wheel = wheelView;
    }

    private List<View> addView(View view, List<View> list) {
        if (list == null) {
            list = new LinkedList<>();
        }
        list.add(view);
        return list;
    }

    private View getCachedView(List<View> list) {
        if (list == null || list.size() <= 0) {
            return null;
        }
        View view = list.get(0);
        list.remove(0);
        return view;
    }

    private void recycleView(View view, int i2) {
        int itemsCount = this.wheel.getViewAdapter().getItemsCount();
        if ((i2 < 0 || i2 >= itemsCount) && !this.wheel.isCyclic()) {
            this.emptyItems = addView(view, this.emptyItems);
            return;
        }
        while (i2 < 0) {
            i2 += itemsCount;
        }
        int i3 = i2 % itemsCount;
        this.items = addView(view, this.items);
    }

    public void clearAll() {
        List<View> list = this.items;
        if (list != null) {
            list.clear();
        }
        List<View> list2 = this.emptyItems;
        if (list2 != null) {
            list2.clear();
        }
    }

    public View getEmptyItem() {
        return getCachedView(this.emptyItems);
    }

    public View getItem() {
        return getCachedView(this.items);
    }

    public int recycleItems(LinearLayout linearLayout, int i2, ItemsRange itemsRange) {
        int i3 = i2;
        int i4 = 0;
        while (i4 < linearLayout.getChildCount()) {
            if (itemsRange.contains(i3)) {
                i4++;
            } else {
                recycleView(linearLayout.getChildAt(i4), i3);
                linearLayout.removeViewAt(i4);
                if (i4 == 0) {
                    i2++;
                }
            }
            i3++;
        }
        return i2;
    }
}
