package T0;

import I0.z;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import b0.AbstractC0311a;
import com.facebook.imagepipeline.nativecode.Bitmaps;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/* JADX INFO: loaded from: classes.dex */
public abstract class a implements d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final Bitmap.Config f2740a = Bitmap.Config.ARGB_8888;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static Method f2741b;

    private static void c(Bitmap bitmap, Bitmap bitmap2) {
        if (!z.a() || bitmap.getConfig() != bitmap2.getConfig()) {
            new Canvas(bitmap).drawBitmap(bitmap2, 0.0f, 0.0f, (Paint) null);
            return;
        }
        try {
            if (f2741b == null) {
                int i3 = Bitmaps.f6069a;
                f2741b = Bitmaps.class.getDeclaredMethod("copyBitmap", Bitmap.class, Bitmap.class);
            }
            f2741b.invoke(null, bitmap, bitmap2);
        } catch (ClassNotFoundException e3) {
            throw new RuntimeException("Wrong Native code setup, reflection failed.", e3);
        } catch (IllegalAccessException e4) {
            throw new RuntimeException("Wrong Native code setup, reflection failed.", e4);
        } catch (NoSuchMethodException e5) {
            throw new RuntimeException("Wrong Native code setup, reflection failed.", e5);
        } catch (InvocationTargetException e6) {
            throw new RuntimeException("Wrong Native code setup, reflection failed.", e6);
        }
    }

    @Override // T0.d
    public AbstractC0311a a(Bitmap bitmap, F0.b bVar) {
        Bitmap.Config config = bitmap.getConfig();
        int width = bitmap.getWidth();
        int height = bitmap.getHeight();
        if (config == null) {
            config = f2740a;
        }
        AbstractC0311a abstractC0311aD = bVar.d(width, height, config);
        try {
            e((Bitmap) abstractC0311aD.P(), bitmap);
            return abstractC0311aD.clone();
        } finally {
            AbstractC0311a.D(abstractC0311aD);
        }
    }

    @Override // T0.d
    public R.d b() {
        return null;
    }

    public void e(Bitmap bitmap, Bitmap bitmap2) {
        c(bitmap, bitmap2);
        d(bitmap);
    }

    @Override // T0.d
    public String getName() {
        return "Unknown postprocessor";
    }

    public void d(Bitmap bitmap) {
    }
}
