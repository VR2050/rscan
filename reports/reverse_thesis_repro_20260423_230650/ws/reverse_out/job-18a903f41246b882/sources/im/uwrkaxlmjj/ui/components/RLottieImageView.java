package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.widget.ImageView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes5.dex */
public class RLottieImageView extends ImageView {
    private RLottieDrawable drawable;
    private HashMap<String, Integer> layerColors;

    public RLottieImageView(Context context) {
        super(context);
    }

    public void setLayerColor(String layer, int color) {
        if (this.layerColors == null) {
            this.layerColors = new HashMap<>();
        }
        this.layerColors.put(layer, Integer.valueOf(color));
        RLottieDrawable rLottieDrawable = this.drawable;
        if (rLottieDrawable != null) {
            rLottieDrawable.setLayerColor(layer, color);
        }
    }

    public void setAnimation(int resId, int w, int h) {
        RLottieDrawable rLottieDrawable = new RLottieDrawable(resId, "" + resId, AndroidUtilities.dp(w), AndroidUtilities.dp(h), false);
        this.drawable = rLottieDrawable;
        rLottieDrawable.beginApplyLayerColors();
        HashMap<String, Integer> map = this.layerColors;
        if (map != null) {
            for (Map.Entry<String, Integer> entry : map.entrySet()) {
                this.drawable.setLayerColor(entry.getKey(), entry.getValue().intValue());
            }
        }
        this.drawable.commitApplyLayerColors();
        this.drawable.setAllowDecodeSingleFrame(true);
        this.drawable.setAutoRepeat(1);
        setImageDrawable(this.drawable);
    }

    public void setProgress(float progress) {
        RLottieDrawable rLottieDrawable = this.drawable;
        if (rLottieDrawable == null) {
            return;
        }
        rLottieDrawable.setProgress(progress);
    }

    public void playAnimation() {
        RLottieDrawable rLottieDrawable = this.drawable;
        if (rLottieDrawable == null) {
            return;
        }
        rLottieDrawable.start();
    }

    public void stopAnimation() {
        RLottieDrawable rLottieDrawable = this.drawable;
        if (rLottieDrawable == null) {
            return;
        }
        rLottieDrawable.start();
    }
}
