package com.lljjcoder.style.citypickerview.widget.wheel.adapters;

import android.content.Context;

/* loaded from: classes2.dex */
public class NumericWheelAdapter extends AbstractWheelTextAdapter {
    public static final int DEFAULT_MAX_VALUE = 9;
    private static final int DEFAULT_MIN_VALUE = 0;
    private String format;
    private int maxValue;
    private int minValue;

    public NumericWheelAdapter(Context context) {
        this(context, 0, 9);
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.adapters.AbstractWheelTextAdapter
    public CharSequence getItemText(int i2) {
        if (i2 < 0 || i2 >= getItemsCount()) {
            return null;
        }
        int i3 = this.minValue + i2;
        String str = this.format;
        return str != null ? String.format(str, Integer.valueOf(i3)) : Integer.toString(i3);
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.adapters.WheelViewAdapter
    public int getItemsCount() {
        return (this.maxValue - this.minValue) + 1;
    }

    public NumericWheelAdapter(Context context, int i2, int i3) {
        this(context, i2, i3, null);
    }

    public NumericWheelAdapter(Context context, int i2, int i3, String str) {
        super(context);
        this.minValue = i2;
        this.maxValue = i3;
        this.format = str;
    }
}
