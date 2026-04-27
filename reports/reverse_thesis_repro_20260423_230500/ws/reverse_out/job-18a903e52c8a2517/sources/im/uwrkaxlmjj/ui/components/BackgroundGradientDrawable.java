package im.uwrkaxlmjj.ui.components;

import android.graphics.drawable.GradientDrawable;

/* JADX INFO: loaded from: classes5.dex */
public class BackgroundGradientDrawable extends GradientDrawable {
    private int[] colors;

    public BackgroundGradientDrawable(GradientDrawable.Orientation orientation, int[] colors) {
        super(orientation, colors);
        this.colors = colors;
    }

    public int[] getColorsList() {
        return this.colors;
    }
}
