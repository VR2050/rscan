package im.uwrkaxlmjj.ui.components.banner.util;

import android.content.res.Resources;
import android.graphics.Outline;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;

/* JADX INFO: loaded from: classes5.dex */
public class BannerUtils {
    public static int getRealPosition(boolean isIncrease, int position, int realCount) {
        if (!isIncrease) {
            return position;
        }
        if (position == 0) {
            int realPosition = realCount - 1;
            return realPosition;
        }
        int realPosition2 = realCount + 1;
        if (position == realPosition2) {
            return 0;
        }
        int realPosition3 = position - 1;
        return realPosition3;
    }

    public static View getView(ViewGroup parent, int layoutId) {
        View view = LayoutInflater.from(parent.getContext()).inflate(layoutId, parent, false);
        ViewGroup.LayoutParams params = view.getLayoutParams();
        if (params.height != -1 || params.width != -1) {
            params.height = -1;
            params.width = -1;
            view.setLayoutParams(params);
        }
        return view;
    }

    public static float dp2px(float dp) {
        return TypedValue.applyDimension(1, dp, Resources.getSystem().getDisplayMetrics());
    }

    public static void setBannerRound(View view, final float radius) {
        view.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.components.banner.util.BannerUtils.1
            @Override // android.view.ViewOutlineProvider
            public void getOutline(View view2, Outline outline) {
                outline.setRoundRect(0, 0, view2.getWidth(), view2.getHeight(), radius);
            }
        });
        view.setClipToOutline(true);
    }
}
