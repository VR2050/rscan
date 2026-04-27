package P1;

import android.view.animation.Interpolator;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class n implements Interpolator {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f2211b = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final float f2212a;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final float a(ReadableMap readableMap) {
            t2.j.f(readableMap, "params");
            if (readableMap.getType("springDamping") == ReadableType.Number) {
                return (float) readableMap.getDouble("springDamping");
            }
            return 0.5f;
        }

        private a() {
        }
    }

    public n(float f3) {
        this.f2212a = f3;
    }

    public static final float a(ReadableMap readableMap) {
        return f2211b.a(readableMap);
    }

    @Override // android.animation.TimeInterpolator
    public float getInterpolation(float f3) {
        double dPow = Math.pow(2.0d, (-10) * f3);
        float f4 = this.f2212a;
        return (float) (((double) 1) + (dPow * Math.sin(((((double) (f3 - (f4 / 4))) * 3.141592653589793d) * ((double) 2)) / ((double) f4))));
    }
}
