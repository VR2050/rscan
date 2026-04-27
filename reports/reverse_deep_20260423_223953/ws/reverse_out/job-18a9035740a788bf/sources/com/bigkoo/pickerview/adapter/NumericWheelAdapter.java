package com.bigkoo.pickerview.adapter;

import com.contrarywind.adapter.WheelAdapter;

/* JADX INFO: loaded from: classes.dex */
public class NumericWheelAdapter implements WheelAdapter {
    private int maxValue;
    private int minValue;

    public NumericWheelAdapter(int minValue, int maxValue) {
        this.minValue = minValue;
        this.maxValue = maxValue;
    }

    @Override // com.contrarywind.adapter.WheelAdapter
    public Object getItem(int index) {
        if (index >= 0 && index < getItemsCount()) {
            int value = this.minValue + index;
            return Integer.valueOf(value);
        }
        return 0;
    }

    @Override // com.contrarywind.adapter.WheelAdapter
    public int getItemsCount() {
        return (this.maxValue - this.minValue) + 1;
    }

    @Override // com.contrarywind.adapter.WheelAdapter
    public int indexOf(Object o) {
        try {
            return ((Integer) o).intValue() - this.minValue;
        } catch (Exception e) {
            return -1;
        }
    }
}
