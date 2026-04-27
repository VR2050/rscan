package com.ding.rtc;

import android.graphics.Color;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteboardTextFormat {
    int color;
    int size;
    int style;

    public void setStyle(int style) {
        this.style = style;
    }

    public void setSize(int size) {
        this.size = size;
    }

    public void setColor(int r, int g, int b, int a) {
        this.color = Color.rgb(r, g, b);
    }

    public void setColor(float r, float g, float b, float a) {
        setColor((int) (r * 255.0f), (int) (g * 255.0f), (int) (b * 255.0f), (int) (255.0f * a));
    }

    public int getStyle() {
        return this.style;
    }

    public int getSize() {
        return this.size;
    }

    public int getColor() {
        return this.color;
    }
}
