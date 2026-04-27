package im.uwrkaxlmjj.ui.components.paint;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public interface Brush {
    float getAlpha();

    float getAngle();

    float getScale();

    float getSpacing();

    Bitmap getStamp();

    boolean isLightSaber();

    public static class Radial implements Brush {
        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getSpacing() {
            return 0.15f;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getAlpha() {
            return 0.85f;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getAngle() {
            return 0.0f;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getScale() {
            return 1.0f;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public boolean isLightSaber() {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public Bitmap getStamp() {
            BitmapFactory.Options options = new BitmapFactory.Options();
            options.inScaled = false;
            return BitmapFactory.decodeResource(ApplicationLoader.applicationContext.getResources(), R.drawable.paint_radial_brush, options);
        }
    }

    public static class Elliptical implements Brush {
        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getSpacing() {
            return 0.04f;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getAlpha() {
            return 0.3f;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getAngle() {
            return (float) Math.toRadians(125.0d);
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getScale() {
            return 1.5f;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public boolean isLightSaber() {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public Bitmap getStamp() {
            BitmapFactory.Options options = new BitmapFactory.Options();
            options.inScaled = false;
            return BitmapFactory.decodeResource(ApplicationLoader.applicationContext.getResources(), R.drawable.paint_elliptical_brush, options);
        }
    }

    public static class Neon implements Brush {
        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getSpacing() {
            return 0.07f;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getAlpha() {
            return 0.7f;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getAngle() {
            return 0.0f;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public float getScale() {
            return 1.45f;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public boolean isLightSaber() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.Brush
        public Bitmap getStamp() {
            BitmapFactory.Options options = new BitmapFactory.Options();
            options.inScaled = false;
            return BitmapFactory.decodeResource(ApplicationLoader.applicationContext.getResources(), R.drawable.paint_neon_brush, options);
        }
    }
}
