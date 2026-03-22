package androidx.dynamicanimation.animation;

import androidx.annotation.FloatRange;
import androidx.annotation.RestrictTo;
import androidx.dynamicanimation.animation.DynamicAnimation;
import com.google.android.material.shadow.ShadowDrawableWrapper;

/* loaded from: classes.dex */
public final class SpringForce implements Force {
    public static final float DAMPING_RATIO_HIGH_BOUNCY = 0.2f;
    public static final float DAMPING_RATIO_LOW_BOUNCY = 0.75f;
    public static final float DAMPING_RATIO_MEDIUM_BOUNCY = 0.5f;
    public static final float DAMPING_RATIO_NO_BOUNCY = 1.0f;
    public static final float STIFFNESS_HIGH = 10000.0f;
    public static final float STIFFNESS_LOW = 200.0f;
    public static final float STIFFNESS_MEDIUM = 1500.0f;
    public static final float STIFFNESS_VERY_LOW = 50.0f;
    private static final double UNSET = Double.MAX_VALUE;
    private static final double VELOCITY_THRESHOLD_MULTIPLIER = 62.5d;
    private double mDampedFreq;
    public double mDampingRatio;
    private double mFinalPosition;
    private double mGammaMinus;
    private double mGammaPlus;
    private boolean mInitialized;
    private final DynamicAnimation.MassState mMassState;
    public double mNaturalFreq;
    private double mValueThreshold;
    private double mVelocityThreshold;

    public SpringForce() {
        this.mNaturalFreq = Math.sqrt(1500.0d);
        this.mDampingRatio = 0.5d;
        this.mInitialized = false;
        this.mFinalPosition = Double.MAX_VALUE;
        this.mMassState = new DynamicAnimation.MassState();
    }

    private void init() {
        if (this.mInitialized) {
            return;
        }
        if (this.mFinalPosition == Double.MAX_VALUE) {
            throw new IllegalStateException("Error: Final position of the spring must be set before the animation starts");
        }
        double d2 = this.mDampingRatio;
        if (d2 > 1.0d) {
            double d3 = this.mNaturalFreq;
            this.mGammaPlus = (Math.sqrt((d2 * d2) - 1.0d) * d3) + ((-d2) * d3);
            double d4 = this.mDampingRatio;
            double d5 = this.mNaturalFreq;
            this.mGammaMinus = ((-d4) * d5) - (Math.sqrt((d4 * d4) - 1.0d) * d5);
        } else if (d2 >= ShadowDrawableWrapper.COS_45 && d2 < 1.0d) {
            this.mDampedFreq = Math.sqrt(1.0d - (d2 * d2)) * this.mNaturalFreq;
        }
        this.mInitialized = true;
    }

    @Override // androidx.dynamicanimation.animation.Force
    @RestrictTo({RestrictTo.Scope.LIBRARY})
    public float getAcceleration(float f2, float f3) {
        float finalPosition = f2 - getFinalPosition();
        double d2 = this.mNaturalFreq;
        return (float) (((-(d2 * d2)) * finalPosition) - (((d2 * 2.0d) * this.mDampingRatio) * f3));
    }

    public float getDampingRatio() {
        return (float) this.mDampingRatio;
    }

    public float getFinalPosition() {
        return (float) this.mFinalPosition;
    }

    public float getStiffness() {
        double d2 = this.mNaturalFreq;
        return (float) (d2 * d2);
    }

    @Override // androidx.dynamicanimation.animation.Force
    @RestrictTo({RestrictTo.Scope.LIBRARY})
    public boolean isAtEquilibrium(float f2, float f3) {
        return ((double) Math.abs(f3)) < this.mVelocityThreshold && ((double) Math.abs(f2 - getFinalPosition())) < this.mValueThreshold;
    }

    public SpringForce setDampingRatio(@FloatRange(from = 0.0d) float f2) {
        if (f2 < 0.0f) {
            throw new IllegalArgumentException("Damping ratio must be non-negative");
        }
        this.mDampingRatio = f2;
        this.mInitialized = false;
        return this;
    }

    public SpringForce setFinalPosition(float f2) {
        this.mFinalPosition = f2;
        return this;
    }

    public SpringForce setStiffness(@FloatRange(from = 0.0d, fromInclusive = false) float f2) {
        if (f2 <= 0.0f) {
            throw new IllegalArgumentException("Spring stiffness constant must be positive.");
        }
        this.mNaturalFreq = Math.sqrt(f2);
        this.mInitialized = false;
        return this;
    }

    public void setValueThreshold(double d2) {
        double abs = Math.abs(d2);
        this.mValueThreshold = abs;
        this.mVelocityThreshold = abs * VELOCITY_THRESHOLD_MULTIPLIER;
    }

    public DynamicAnimation.MassState updateValues(double d2, double d3, long j2) {
        double cos;
        double d4;
        init();
        double d5 = j2 / 1000.0d;
        double d6 = d2 - this.mFinalPosition;
        double d7 = this.mDampingRatio;
        if (d7 > 1.0d) {
            double d8 = this.mGammaMinus;
            double d9 = this.mGammaPlus;
            double d10 = d6 - (((d8 * d6) - d3) / (d8 - d9));
            double d11 = ((d6 * d8) - d3) / (d8 - d9);
            d4 = (Math.pow(2.718281828459045d, this.mGammaPlus * d5) * d11) + (Math.pow(2.718281828459045d, d8 * d5) * d10);
            double d12 = this.mGammaMinus;
            double pow = Math.pow(2.718281828459045d, d12 * d5) * d10 * d12;
            double d13 = this.mGammaPlus;
            cos = (Math.pow(2.718281828459045d, d13 * d5) * d11 * d13) + pow;
        } else if (d7 == 1.0d) {
            double d14 = this.mNaturalFreq;
            double d15 = (d14 * d6) + d3;
            double d16 = (d15 * d5) + d6;
            double pow2 = Math.pow(2.718281828459045d, (-d14) * d5) * d16;
            double pow3 = Math.pow(2.718281828459045d, (-this.mNaturalFreq) * d5) * d16;
            double d17 = this.mNaturalFreq;
            cos = (Math.pow(2.718281828459045d, (-d17) * d5) * d15) + (pow3 * (-d17));
            d4 = pow2;
        } else {
            double d18 = 1.0d / this.mDampedFreq;
            double d19 = this.mNaturalFreq;
            double d20 = ((d7 * d19 * d6) + d3) * d18;
            double sin = ((Math.sin(this.mDampedFreq * d5) * d20) + (Math.cos(this.mDampedFreq * d5) * d6)) * Math.pow(2.718281828459045d, (-d7) * d19 * d5);
            double d21 = this.mNaturalFreq;
            double d22 = this.mDampingRatio;
            double d23 = (-d21) * sin * d22;
            double pow4 = Math.pow(2.718281828459045d, (-d22) * d21 * d5);
            double d24 = this.mDampedFreq;
            double sin2 = Math.sin(d24 * d5) * (-d24) * d6;
            double d25 = this.mDampedFreq;
            cos = (((Math.cos(d25 * d5) * d20 * d25) + sin2) * pow4) + d23;
            d4 = sin;
        }
        DynamicAnimation.MassState massState = this.mMassState;
        massState.mValue = (float) (d4 + this.mFinalPosition);
        massState.mVelocity = (float) cos;
        return massState;
    }

    public SpringForce(float f2) {
        this.mNaturalFreq = Math.sqrt(1500.0d);
        this.mDampingRatio = 0.5d;
        this.mInitialized = false;
        this.mFinalPosition = Double.MAX_VALUE;
        this.mMassState = new DynamicAnimation.MassState();
        this.mFinalPosition = f2;
    }
}
