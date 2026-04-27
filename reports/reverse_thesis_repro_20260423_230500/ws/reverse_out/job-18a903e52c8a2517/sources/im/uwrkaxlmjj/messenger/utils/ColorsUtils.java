package im.uwrkaxlmjj.messenger.utils;

import android.graphics.Color;

/* JADX INFO: loaded from: classes2.dex */
public class ColorsUtils {
    public static int getDarkerColor(int color) {
        float[] hsv = new float[3];
        Color.colorToHSV(color, hsv);
        hsv[2] = hsv[2] - 0.1f;
        return Color.HSVToColor(hsv);
    }

    public int getLrighterColor(int color) {
        float[] hsv = new float[3];
        Color.colorToHSV(color, hsv);
        hsv[1] = hsv[1] - 0.1f;
        hsv[2] = hsv[2] + 0.1f;
        int darkerColor = Color.HSVToColor(hsv);
        return darkerColor;
    }
}
