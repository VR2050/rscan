package im.uwrkaxlmjj.ui.load.animation.interpolator;

import android.animation.TimeInterpolator;
import android.view.animation.Interpolator;

/* JADX INFO: loaded from: classes5.dex */
public class KeyFrameInterpolator implements Interpolator {
    private float[] fractions;
    private TimeInterpolator interpolator;

    public static KeyFrameInterpolator easeInOut(float... fractions) {
        KeyFrameInterpolator interpolator = new KeyFrameInterpolator(Ease.inOut(), new float[0]);
        interpolator.setFractions(fractions);
        return interpolator;
    }

    public static KeyFrameInterpolator pathInterpolator(float controlX1, float controlY1, float controlX2, float controlY2, float... fractions) {
        KeyFrameInterpolator interpolator = new KeyFrameInterpolator(PathInterpolatorCompat.create(controlX1, controlY1, controlX2, controlY2), new float[0]);
        interpolator.setFractions(fractions);
        return interpolator;
    }

    public KeyFrameInterpolator(TimeInterpolator interpolator, float... fractions) {
        this.interpolator = interpolator;
        this.fractions = fractions;
    }

    public void setFractions(float... fractions) {
        this.fractions = fractions;
    }

    @Override // android.animation.TimeInterpolator
    public float getInterpolation(float input) {
        if (this.fractions.length > 1) {
            int i = 0;
            while (true) {
                float[] fArr = this.fractions;
                if (i >= fArr.length - 1) {
                    break;
                }
                float start = fArr[i];
                float end = fArr[i + 1];
                float duration = end - start;
                if (input < start || input > end) {
                    i++;
                } else {
                    return (this.interpolator.getInterpolation((input - start) / duration) * duration) + start;
                }
            }
        }
        return this.interpolator.getInterpolation(input);
    }
}
