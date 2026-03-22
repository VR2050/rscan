package com.lljjcoder.style.citypickerview.widget.wheel.adapters;

import android.content.Context;
import com.lljjcoder.style.citypickerview.widget.wheel.WheelAdapter;

/* loaded from: classes2.dex */
public class AdapterWheel extends AbstractWheelTextAdapter {
    private WheelAdapter adapter;

    public AdapterWheel(Context context, WheelAdapter wheelAdapter) {
        super(context);
        this.adapter = wheelAdapter;
    }

    public WheelAdapter getAdapter() {
        return this.adapter;
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.adapters.AbstractWheelTextAdapter
    public CharSequence getItemText(int i2) {
        return this.adapter.getItem(i2);
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.adapters.WheelViewAdapter
    public int getItemsCount() {
        return this.adapter.getItemsCount();
    }
}
