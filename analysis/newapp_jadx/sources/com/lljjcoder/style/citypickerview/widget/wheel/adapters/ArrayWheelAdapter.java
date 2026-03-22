package com.lljjcoder.style.citypickerview.widget.wheel.adapters;

import android.content.Context;
import java.util.List;

/* loaded from: classes2.dex */
public class ArrayWheelAdapter<T> extends AbstractWheelTextAdapter {
    private List<T> items;

    public ArrayWheelAdapter(Context context, List<T> list) {
        super(context);
        this.items = list;
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.adapters.AbstractWheelTextAdapter
    public CharSequence getItemText(int i2) {
        if (i2 < 0 || i2 >= this.items.size()) {
            return null;
        }
        T t = this.items.get(i2);
        return t instanceof CharSequence ? (CharSequence) t : t.toString();
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.adapters.WheelViewAdapter
    public int getItemsCount() {
        return this.items.size();
    }
}
