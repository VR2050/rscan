package androidx.constraintlayout.motion.utils;

import com.google.android.material.shadow.ShadowDrawableWrapper;
import java.util.Arrays;

/* loaded from: classes.dex */
public class Easing {
    private static final String ACCELERATE = "cubic(0.4, 0.05, 0.8, 0.7)";
    private static final String DECELERATE = "cubic(0.0, 0.0, 0.2, 0.95)";
    private static final String LINEAR = "cubic(1, 1, 0, 0)";
    private static final String STANDARD = "cubic(0.4, 0.0, 0.2, 1)";
    public String str = "identity";
    public static Easing sDefault = new Easing();
    private static final String STANDARD_NAME = "standard";
    private static final String ACCELERATE_NAME = "accelerate";
    private static final String DECELERATE_NAME = "decelerate";
    private static final String LINEAR_NAME = "linear";
    public static String[] NAMED_EASING = {STANDARD_NAME, ACCELERATE_NAME, DECELERATE_NAME, LINEAR_NAME};

    public static Easing getInterpolator(String str) {
        if (str == null) {
            return null;
        }
        if (str.startsWith("cubic")) {
            return new CubicEasing(str);
        }
        switch (str) {
            case "accelerate":
                return new CubicEasing(ACCELERATE);
            case "decelerate":
                return new CubicEasing(DECELERATE);
            case "linear":
                return new CubicEasing(LINEAR);
            case "standard":
                return new CubicEasing(STANDARD);
            default:
                Arrays.toString(NAMED_EASING);
                return sDefault;
        }
    }

    public double get(double d2) {
        return d2;
    }

    public double getDiff(double d2) {
        return 1.0d;
    }

    public String toString() {
        return this.str;
    }

    public static class CubicEasing extends Easing {
        private static double d_error = 1.0E-4d;
        private static double error = 0.01d;

        /* renamed from: x1 */
        public double f118x1;

        /* renamed from: x2 */
        public double f119x2;

        /* renamed from: y1 */
        public double f120y1;

        /* renamed from: y2 */
        public double f121y2;

        public CubicEasing(String str) {
            this.str = str;
            int indexOf = str.indexOf(40);
            int indexOf2 = str.indexOf(44, indexOf);
            this.f118x1 = Double.parseDouble(str.substring(indexOf + 1, indexOf2).trim());
            int i2 = indexOf2 + 1;
            int indexOf3 = str.indexOf(44, i2);
            this.f120y1 = Double.parseDouble(str.substring(i2, indexOf3).trim());
            int i3 = indexOf3 + 1;
            int indexOf4 = str.indexOf(44, i3);
            this.f119x2 = Double.parseDouble(str.substring(i3, indexOf4).trim());
            int i4 = indexOf4 + 1;
            this.f121y2 = Double.parseDouble(str.substring(i4, str.indexOf(41, i4)).trim());
        }

        private double getDiffX(double d2) {
            double d3 = 1.0d - d2;
            double d4 = this.f118x1;
            double d5 = d3 * 3.0d * d3 * d4;
            double d6 = this.f119x2;
            return ((1.0d - d6) * 3.0d * d2 * d2) + ((d6 - d4) * d3 * 6.0d * d2) + d5;
        }

        private double getDiffY(double d2) {
            double d3 = 1.0d - d2;
            double d4 = this.f120y1;
            double d5 = d3 * 3.0d * d3 * d4;
            double d6 = this.f121y2;
            return ((1.0d - d6) * 3.0d * d2 * d2) + ((d6 - d4) * d3 * 6.0d * d2) + d5;
        }

        private double getX(double d2) {
            double d3 = 1.0d - d2;
            double d4 = 3.0d * d3;
            double d5 = d3 * d4 * d2;
            double d6 = d4 * d2 * d2;
            return (this.f119x2 * d6) + (this.f118x1 * d5) + (d2 * d2 * d2);
        }

        private double getY(double d2) {
            double d3 = 1.0d - d2;
            double d4 = 3.0d * d3;
            double d5 = d3 * d4 * d2;
            double d6 = d4 * d2 * d2;
            return (this.f121y2 * d6) + (this.f120y1 * d5) + (d2 * d2 * d2);
        }

        @Override // androidx.constraintlayout.motion.utils.Easing
        public double get(double d2) {
            if (d2 <= ShadowDrawableWrapper.COS_45) {
                return ShadowDrawableWrapper.COS_45;
            }
            if (d2 >= 1.0d) {
                return 1.0d;
            }
            double d3 = 0.5d;
            double d4 = 0.5d;
            while (d3 > error) {
                d3 *= 0.5d;
                d4 = getX(d4) < d2 ? d4 + d3 : d4 - d3;
            }
            double d5 = d4 - d3;
            double x = getX(d5);
            double d6 = d4 + d3;
            double x2 = getX(d6);
            double y = getY(d5);
            return (((d2 - x) * (getY(d6) - y)) / (x2 - x)) + y;
        }

        @Override // androidx.constraintlayout.motion.utils.Easing
        public double getDiff(double d2) {
            double d3 = 0.5d;
            double d4 = 0.5d;
            while (d3 > d_error) {
                d3 *= 0.5d;
                d4 = getX(d4) < d2 ? d4 + d3 : d4 - d3;
            }
            double d5 = d4 - d3;
            double d6 = d4 + d3;
            return (getY(d6) - getY(d5)) / (getX(d6) - getX(d5));
        }

        public void setup(double d2, double d3, double d4, double d5) {
            this.f118x1 = d2;
            this.f120y1 = d3;
            this.f119x2 = d4;
            this.f121y2 = d5;
        }

        public CubicEasing(double d2, double d3, double d4, double d5) {
            setup(d2, d3, d4, d5);
        }
    }
}
