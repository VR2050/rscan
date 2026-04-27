package com.bigkoo.pickerview.adapter;

import com.contrarywind.adapter.WheelAdapter;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public class ArrayWheelAdapter<T> implements WheelAdapter {
    private List<T> items;

    public ArrayWheelAdapter(List<T> items) {
        this.items = items;
    }

    @Override // com.contrarywind.adapter.WheelAdapter
    public Object getItem(int index) {
        if (index >= 0 && index < this.items.size()) {
            return this.items.get(index);
        }
        return "";
    }

    @Override // com.contrarywind.adapter.WheelAdapter
    public int getItemsCount() {
        return this.items.size();
    }

    @Override // com.contrarywind.adapter.WheelAdapter
    public int indexOf(Object o) {
        return this.items.indexOf(o);
    }
}
