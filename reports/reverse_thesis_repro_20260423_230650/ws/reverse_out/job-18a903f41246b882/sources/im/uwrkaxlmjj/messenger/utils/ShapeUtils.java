package im.uwrkaxlmjj.messenger.utils;

import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes2.dex */
public class ShapeUtils {
    public static ShapeDrawable create(int bgColor, float cornerRadius) {
        return new ShapeDrawable.Builder().gradientType(0).solidColor(bgColor).cornerRadius(cornerRadius).build();
    }

    public static GradientDrawable createGradient(float cornerRadius, int[] colors, GradientDrawable.Orientation orientation) {
        GradientDrawable gradientDrawable = new GradientDrawable(orientation, colors);
        gradientDrawable.setCornerRadius(AndroidUtilities.dp(cornerRadius));
        return gradientDrawable;
    }

    public static ShapeDrawable createTop(int bgColor, float cornerRadiusLeftTop, float cornerRadiusRightTop) {
        return new ShapeDrawable.Builder().gradientType(0).solidColor(bgColor).cornerRadiusLeftTop(cornerRadiusLeftTop).cornerRadiusRightTop(cornerRadiusRightTop).build();
    }

    public static ShapeDrawable createLeftAndBottom(int bgColor, float cornerRadiusLeftTop, float cornerRadiusLeftBottom) {
        return new ShapeDrawable.Builder().gradientType(0).solidColor(bgColor).cornerRadiusLeftTop(cornerRadiusLeftTop).cornerRadiusLeftBottom(cornerRadiusLeftBottom).build();
    }

    public static ShapeDrawable createBottom(int bgColor, float cornerRadiusLeftBottom, float cornerRadiusRightBottom) {
        return new ShapeDrawable.Builder().gradientType(0).solidColor(bgColor).cornerRadiusLeftBottom(cornerRadiusLeftBottom).cornerRadiusRightBottom(cornerRadiusRightBottom).build();
    }

    public static ShapeDrawable createOnlyStroke(int strokeColor, float strokeWidth, float cornerRadius) {
        return new ShapeDrawable.Builder().gradientType(0).strokeColor(strokeColor).strokeWidth(strokeWidth).cornerRadius(cornerRadius).build();
    }

    public static ShapeDrawable createStrokeAndFill(int strokeColor, float strokeWidth, float cornerRadius, int solidColor) {
        return new ShapeDrawable.Builder().gradientType(0).strokeColor(strokeColor).strokeWidth(strokeWidth).cornerRadius(cornerRadius).solidColor(solidColor).build();
    }

    public static ShapeDrawable createOnlyFill(float cornerRadius, int solidColor) {
        return new ShapeDrawable.Builder().gradientType(0).cornerRadius(cornerRadius).solidColor(solidColor).build();
    }

    public static class ShapeDrawable extends GradientDrawable {
        public static final int LINE = 2;
        public static final int OVAL = 1;
        public static final int RECTANGLE = 0;
        private float cornerRadius;
        private float cornerRadiusLeftBottom;
        private float cornerRadiusLeftTop;
        private float cornerRadiusRightBottom;
        private float cornerRadiusRightTop;
        private float dashGap;
        private float dashWidth;
        private int gradientType;
        private int solidColor;
        private int strokeColor;
        private float strokeWidth;

        public ShapeDrawable(int gradientType, int solidColor, int strokeColor, float cornerRadius, float strokeWidth, float dashGap, float dashWidth) {
            this.gradientType = gradientType;
            this.solidColor = solidColor;
            this.strokeColor = strokeColor;
            this.cornerRadius = cornerRadius;
            this.strokeWidth = strokeWidth;
            this.dashGap = dashGap;
            this.dashWidth = dashWidth;
        }

        /* JADX WARN: Removed duplicated region for block: B:15:0x007f  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        private ShapeDrawable(im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder r6) {
            /*
                r5 = this;
                r5.<init>()
                int r0 = im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder.access$000(r6)
                r5.gradientType = r0
                int r0 = im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder.access$100(r6)
                r5.solidColor = r0
                int r0 = im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder.access$200(r6)
                r5.strokeColor = r0
                float r0 = im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder.access$300(r6)
                r5.cornerRadius = r0
                float r0 = im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder.access$400(r6)
                r5.strokeWidth = r0
                float r0 = im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder.access$500(r6)
                r5.dashGap = r0
                float r0 = im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder.access$600(r6)
                r5.dashWidth = r0
                float r0 = im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder.access$700(r6)
                r5.cornerRadiusLeftTop = r0
                float r0 = im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder.access$800(r6)
                r5.cornerRadiusLeftBottom = r0
                float r0 = im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder.access$900(r6)
                r5.cornerRadiusRightTop = r0
                float r0 = im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.Builder.access$1000(r6)
                r5.cornerRadiusRightBottom = r0
                int r0 = r5.gradientType
                r5.setGradientType(r0)
                int r0 = r5.solidColor
                java.lang.String r1 = "#00000000"
                if (r0 != 0) goto L54
                int r0 = android.graphics.Color.parseColor(r1)
            L54:
                r5.solidColor = r0
                int r0 = r5.strokeColor
                if (r0 != 0) goto L5e
                int r0 = android.graphics.Color.parseColor(r1)
            L5e:
                r5.strokeColor = r0
                int r0 = r5.solidColor
                r5.setColor(r0)
                float r0 = r5.strokeWidth
                r1 = 0
                int r2 = (r0 > r1 ? 1 : (r0 == r1 ? 0 : -1))
                if (r2 == 0) goto L87
                float r2 = r5.dashGap
                int r3 = (r2 > r1 ? 1 : (r2 == r1 ? 0 : -1))
                if (r3 == 0) goto L7f
                float r3 = r5.dashWidth
                int r4 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
                if (r4 == 0) goto L7f
                int r0 = (int) r0
                int r4 = r5.strokeColor
                r5.setStroke(r0, r4, r2, r3)
                goto L87
            L7f:
                float r0 = r5.strokeWidth
                int r0 = (int) r0
                int r2 = r5.strokeColor
                r5.setStroke(r0, r2)
            L87:
                float r0 = r5.cornerRadius
                int r1 = (r0 > r1 ? 1 : (r0 == r1 ? 0 : -1))
                if (r1 <= 0) goto L91
                r5.setCornerRadius(r0)
                goto Lb8
            L91:
                r0 = 8
                float[] r0 = new float[r0]
                r1 = 0
                float r2 = r5.cornerRadiusLeftTop
                r0[r1] = r2
                r1 = 1
                r0[r1] = r2
                r1 = 2
                float r2 = r5.cornerRadiusRightTop
                r0[r1] = r2
                r1 = 3
                r0[r1] = r2
                r1 = 4
                float r2 = r5.cornerRadiusRightBottom
                r0[r1] = r2
                r1 = 5
                r0[r1] = r2
                r1 = 6
                float r2 = r5.cornerRadiusLeftBottom
                r0[r1] = r2
                r1 = 7
                r0[r1] = r2
                r5.setCornerRadii(r0)
            Lb8:
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.utils.ShapeUtils.ShapeDrawable.<init>(im.uwrkaxlmjj.messenger.utils.ShapeUtils$ShapeDrawable$Builder):void");
        }

        public static final class Builder {
            private float cornerRadius;
            private float cornerRadiusLeftBottom;
            private float cornerRadiusLeftTop;
            private float cornerRadiusRightBottom;
            private float cornerRadiusRightTop;
            private float dashGap;
            private float dashWidth;
            private int gradientType;
            private int solidColor;
            private int strokeColor;
            private float strokeWidth;

            public Builder cornerRadiusLeftTop(float val) {
                this.cornerRadiusLeftTop = val;
                return this;
            }

            public Builder cornerRadiusLeftBottom(float val) {
                this.cornerRadiusLeftBottom = val;
                return this;
            }

            public Builder cornerRadiusRightTop(float val) {
                this.cornerRadiusRightTop = val;
                return this;
            }

            public Builder cornerRadiusRightBottom(float val) {
                this.cornerRadiusRightBottom = val;
                return this;
            }

            public Builder gradientType(int val) {
                this.gradientType = val;
                return this;
            }

            public Builder solidColor(int val) {
                this.solidColor = val;
                return this;
            }

            public Builder solidColor(String val) {
                this.solidColor = Color.parseColor(val);
                return this;
            }

            public Builder strokeColor(int val) {
                this.strokeColor = val;
                return this;
            }

            public Builder strokeColor(String val) {
                this.strokeColor = Color.parseColor(val);
                return this;
            }

            public Builder cornerRadius(float val) {
                this.cornerRadius = val;
                return this;
            }

            public Builder strokeWidth(float val) {
                this.strokeWidth = val;
                return this;
            }

            public Builder dashGap(float val) {
                this.dashGap = val;
                return this;
            }

            public Builder dashWidth(float val) {
                this.dashWidth = val;
                return this;
            }

            public ShapeDrawable build() {
                return new ShapeDrawable(this);
            }
        }
    }
}
