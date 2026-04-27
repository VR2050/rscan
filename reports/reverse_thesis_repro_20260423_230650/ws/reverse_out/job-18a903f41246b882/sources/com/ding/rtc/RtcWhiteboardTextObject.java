package com.ding.rtc;

import android.graphics.Color;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteboardTextObject {
    public String text;
    public RtcWhiteboardTextFormat format = new RtcWhiteboardTextFormat();
    public float x = 0.0f;
    public float y = 0.0f;
    float w = 0.0f;
    float h = 0.0f;

    public void setStyle(int style) {
        this.format.style = style;
    }

    public void setSize(int size) {
        this.format.size = size;
    }

    public void setColor(int r, int g, int b, int a) {
        this.format.color = Color.rgb(r, g, b);
    }

    public void setColor(float r, float g, float b, float a) {
        setColor((int) (r * 255.0f), (int) (g * 255.0f), (int) (b * 255.0f), (int) (255.0f * a));
    }

    public void setText(String text) {
        this.text = text;
    }

    public void setRect(float x, float y, float w, float h) {
        this.x = x;
        this.y = y;
        this.w = w;
        this.h = h;
    }

    public int getStyle() {
        return this.format.style;
    }

    public int getSize() {
        return this.format.size;
    }

    public int getColor() {
        return this.format.color;
    }

    public String getText() {
        return this.text;
    }

    public float getX() {
        return this.x;
    }

    public float getY() {
        return this.y;
    }

    public float getWidth() {
        return this.w;
    }

    public float getHeight() {
        return this.h;
    }
}
