package com.scwang.smartrefresh.layout.constant;

/* JADX INFO: loaded from: classes3.dex */
public class SpinnerStyle {
    public static final SpinnerStyle MatchLayout;
    public static final SpinnerStyle[] values;
    public final boolean front;
    public final int ordinal;
    public final boolean scale;
    public static final SpinnerStyle Translate = new SpinnerStyle(0, true, false);

    @Deprecated
    public static final SpinnerStyle Scale = new SpinnerStyle(1, true, true);
    public static final SpinnerStyle FixedBehind = new SpinnerStyle(2, false, false);
    public static final SpinnerStyle FixedFront = new SpinnerStyle(3, true, false);

    static {
        SpinnerStyle spinnerStyle = new SpinnerStyle(4, true, false);
        MatchLayout = spinnerStyle;
        values = new SpinnerStyle[]{Translate, Scale, FixedBehind, FixedFront, spinnerStyle};
    }

    private SpinnerStyle(int ordinal, boolean front, boolean scale) {
        this.ordinal = ordinal;
        this.front = front;
        this.scale = scale;
    }
}
