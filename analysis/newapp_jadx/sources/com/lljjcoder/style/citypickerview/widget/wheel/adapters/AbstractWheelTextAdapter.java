package com.lljjcoder.style.citypickerview.widget.wheel.adapters;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

/* loaded from: classes2.dex */
public abstract class AbstractWheelTextAdapter extends AbstractWheelAdapter {
    public static final int DEFAULT_TEXT_COLOR = -10987432;
    public static final int DEFAULT_TEXT_SIZE = 18;
    public static final int LABEL_COLOR = -9437072;
    public static final int NO_RESOURCE = 0;
    public static final int TEXT_VIEW_ITEM_RESOURCE = -1;
    public Context context;
    public int emptyItemResourceId;
    public LayoutInflater inflater;
    public int itemResourceId;
    public int itemTextResourceId;
    private int padding;
    private int textColor;
    private int textSize;

    public AbstractWheelTextAdapter(Context context) {
        this(context, -1);
    }

    private TextView getTextView(View view, int i2) {
        TextView textView;
        if (i2 == 0) {
            try {
                if (view instanceof TextView) {
                    textView = (TextView) view;
                    return textView;
                }
            } catch (ClassCastException e2) {
                throw new IllegalStateException("AbstractWheelAdapter requires the resource ID to be a TextView", e2);
            }
        }
        textView = i2 != 0 ? (TextView) view.findViewById(i2) : null;
        return textView;
    }

    private View getView(int i2, ViewGroup viewGroup) {
        if (i2 == -1) {
            return new TextView(this.context);
        }
        if (i2 != 0) {
            return this.inflater.inflate(i2, viewGroup, false);
        }
        return null;
    }

    public void configureTextView(TextView textView) {
        textView.setTextColor(this.textColor);
        textView.setGravity(17);
        int i2 = this.padding;
        textView.setPadding(0, i2, 0, i2);
        textView.setTextSize(this.textSize);
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.adapters.AbstractWheelAdapter, com.lljjcoder.style.citypickerview.widget.wheel.adapters.WheelViewAdapter
    public View getEmptyItem(View view, ViewGroup viewGroup) {
        if (view == null) {
            view = getView(this.emptyItemResourceId, viewGroup);
        }
        if (this.emptyItemResourceId == -1 && (view instanceof TextView)) {
            configureTextView((TextView) view);
        }
        return view;
    }

    public int getEmptyItemResource() {
        return this.emptyItemResourceId;
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.adapters.WheelViewAdapter
    public View getItem(int i2, View view, ViewGroup viewGroup) {
        if (i2 < 0 || i2 >= getItemsCount()) {
            return null;
        }
        if (view == null) {
            view = getView(this.itemResourceId, viewGroup);
        }
        TextView textView = getTextView(view, this.itemTextResourceId);
        if (textView != null) {
            CharSequence itemText = getItemText(i2);
            if (itemText == null) {
                itemText = "";
            }
            textView.setText(itemText);
            if (this.itemResourceId == -1) {
                configureTextView(textView);
            }
        }
        return view;
    }

    public int getItemResource() {
        return this.itemResourceId;
    }

    public abstract CharSequence getItemText(int i2);

    public int getItemTextResource() {
        return this.itemTextResourceId;
    }

    public int getPadding() {
        return this.padding;
    }

    public int getTextColor() {
        return this.textColor;
    }

    public int getTextSize() {
        return this.textSize;
    }

    public void setEmptyItemResource(int i2) {
        this.emptyItemResourceId = i2;
    }

    public void setItemResource(int i2) {
        this.itemResourceId = i2;
    }

    public void setItemTextResource(int i2) {
        this.itemTextResourceId = i2;
    }

    public void setPadding(int i2) {
        this.padding = i2;
    }

    public void setTextColor(int i2) {
        this.textColor = i2;
    }

    public void setTextSize(int i2) {
        this.textSize = i2;
    }

    public AbstractWheelTextAdapter(Context context, int i2) {
        this(context, i2, 0);
    }

    public AbstractWheelTextAdapter(Context context, int i2, int i3) {
        this.textColor = DEFAULT_TEXT_COLOR;
        this.textSize = 18;
        this.padding = 5;
        this.context = context;
        this.itemResourceId = i2;
        this.itemTextResourceId = i3;
        this.inflater = (LayoutInflater) context.getSystemService("layout_inflater");
    }
}
