package androidx.camera.view.preview.transform;

import android.util.Pair;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.camera.view.PreviewView;
import androidx.camera.view.preview.transform.transformation.ScaleTransformation;
import androidx.camera.view.preview.transform.transformation.Transformation;
import androidx.camera.view.preview.transform.transformation.TranslationTransformation;

/* loaded from: classes.dex */
public final class ScaleTypeTransform {

    /* renamed from: androidx.camera.view.preview.transform.ScaleTypeTransform$1 */
    public static /* synthetic */ class C02201 {
        public static final /* synthetic */ int[] $SwitchMap$androidx$camera$view$PreviewView$ScaleType;

        static {
            PreviewView.ScaleType.values();
            int[] iArr = new int[6];
            $SwitchMap$androidx$camera$view$PreviewView$ScaleType = iArr;
            try {
                iArr[PreviewView.ScaleType.FILL_START.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[PreviewView.ScaleType.FILL_CENTER.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[PreviewView.ScaleType.FILL_END.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[PreviewView.ScaleType.FIT_START.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[PreviewView.ScaleType.FIT_CENTER.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[PreviewView.ScaleType.FIT_END.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
        }
    }

    private ScaleTypeTransform() {
    }

    private static ScaleTransformation getScale(@NonNull View view, @NonNull View view2, @NonNull PreviewView.ScaleType scaleType, int i2) {
        int ordinal = scaleType.ordinal();
        if (ordinal == 0 || ordinal == 1 || ordinal == 2) {
            return ScaleTransform.fill(view, view2, i2);
        }
        if (ordinal == 3 || ordinal == 4 || ordinal == 5) {
            return ScaleTransform.fit(view, view2, i2);
        }
        throw new IllegalArgumentException("Unknown scale type " + scaleType);
    }

    private static TranslationTransformation getScaledTranslation(@NonNull View view, @NonNull View view2, @NonNull PreviewView.ScaleType scaleType, @NonNull Pair<Float, Float> pair, int i2) {
        int ordinal = scaleType.ordinal();
        if (ordinal != 0) {
            if (ordinal != 1) {
                if (ordinal != 2) {
                    if (ordinal != 3) {
                        if (ordinal != 4) {
                            if (ordinal != 5) {
                                throw new IllegalArgumentException("Unknown scale type " + scaleType);
                            }
                        }
                    }
                }
                return TranslationTransform.end(view, view2, pair, i2);
            }
            return TranslationTransform.center(view, view2);
        }
        return TranslationTransform.start(view2, pair, i2);
    }

    public static Transformation getTransformation(@NonNull View view, @NonNull View view2, @NonNull PreviewView.ScaleType scaleType, int i2) {
        ScaleTransformation scale = getScale(view, view2, scaleType, i2);
        return scale.add(getScaledTranslation(view, view2, scaleType, new Pair(Float.valueOf(scale.getScaleX() * view2.getScaleX()), Float.valueOf(scale.getScaleY() * view2.getScaleY())), i2));
    }
}
