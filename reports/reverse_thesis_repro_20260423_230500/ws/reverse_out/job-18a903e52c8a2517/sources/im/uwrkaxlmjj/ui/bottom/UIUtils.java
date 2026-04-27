package im.uwrkaxlmjj.ui.bottom;

import android.content.Context;
import android.graphics.drawable.Drawable;

/* JADX INFO: loaded from: classes5.dex */
public class UIUtils {
    public static int dip2Px(Context context, int dip) {
        float density = context.getResources().getDisplayMetrics().density;
        int px = (int) ((dip * density) + 0.5f);
        return px;
    }

    public static int sp2px(Context context, float spValue) {
        float fontScale = context.getResources().getDisplayMetrics().scaledDensity;
        return (int) ((spValue * fontScale) + 0.5f);
    }

    public static int getColor(Context context, int colorId) {
        return context.getResources().getColor(colorId);
    }

    public static Drawable getDrawable(Context context, int resId) {
        return context.getResources().getDrawable(resId);
    }
}
