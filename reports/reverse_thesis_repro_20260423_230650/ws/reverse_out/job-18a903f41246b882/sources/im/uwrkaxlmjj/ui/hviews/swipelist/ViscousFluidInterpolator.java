package im.uwrkaxlmjj.ui.hviews.swipelist;

import android.view.animation.Interpolator;

/* JADX INFO: loaded from: classes5.dex */
public class ViscousFluidInterpolator implements Interpolator {
    private final float mViscousFluidNormalize;
    private final float mViscousFluidOffset;
    private final float mViscousFluidScale;

    public ViscousFluidInterpolator() {
        this(8.0f);
    }

    public ViscousFluidInterpolator(float viscousFluidScale) {
        this.mViscousFluidScale = viscousFluidScale;
        float fViscousFluid = 1.0f / viscousFluid(1.0f);
        this.mViscousFluidNormalize = fViscousFluid;
        this.mViscousFluidOffset = 1.0f - (fViscousFluid * viscousFluid(1.0f));
    }

    private float viscousFluid(float x) {
        float x2 = x * this.mViscousFluidScale;
        if (x2 < 1.0f) {
            return x2 - (1.0f - ((float) Math.exp(-x2)));
        }
        return 0.36787945f + ((1.0f - 0.36787945f) * (1.0f - ((float) Math.exp(1.0f - x2))));
    }

    @Override // android.animation.TimeInterpolator
    public float getInterpolation(float input) {
        float interpolated = this.mViscousFluidNormalize * viscousFluid(input);
        if (interpolated > 0.0f) {
            return this.mViscousFluidOffset + interpolated;
        }
        return interpolated;
    }
}
