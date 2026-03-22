package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.os.Build;
import android.util.Log;
import androidx.annotation.NonNull;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;

/* renamed from: b.g.a.m.v.c.b0 */
/* loaded from: classes.dex */
public final class C1694b0 {

    /* renamed from: a */
    public static final Paint f2468a = new Paint(6);

    /* renamed from: b */
    public static final Paint f2469b = new Paint(7);

    /* renamed from: c */
    public static final Paint f2470c;

    /* renamed from: d */
    public static final Set<String> f2471d;

    /* renamed from: e */
    public static final Lock f2472e;

    /* renamed from: b.g.a.m.v.c.b0$a */
    public static final class a implements Lock {
        @Override // java.util.concurrent.locks.Lock
        public void lock() {
        }

        @Override // java.util.concurrent.locks.Lock
        public void lockInterruptibly() {
        }

        @Override // java.util.concurrent.locks.Lock
        @NonNull
        public Condition newCondition() {
            throw new UnsupportedOperationException("Should not be called");
        }

        @Override // java.util.concurrent.locks.Lock
        public boolean tryLock() {
            return true;
        }

        @Override // java.util.concurrent.locks.Lock
        public boolean tryLock(long j2, @NonNull TimeUnit timeUnit) {
            return true;
        }

        @Override // java.util.concurrent.locks.Lock
        public void unlock() {
        }
    }

    static {
        HashSet hashSet = new HashSet(Arrays.asList("XT1085", "XT1092", "XT1093", "XT1094", "XT1095", "XT1096", "XT1097", "XT1098", "XT1031", "XT1028", "XT937C", "XT1032", "XT1008", "XT1033", "XT1035", "XT1034", "XT939G", "XT1039", "XT1040", "XT1042", "XT1045", "XT1063", "XT1064", "XT1068", "XT1069", "XT1072", "XT1077", "XT1078", "XT1079"));
        f2471d = hashSet;
        f2472e = hashSet.contains(Build.MODEL) ? new ReentrantLock() : new a();
        Paint paint = new Paint(7);
        f2470c = paint;
        paint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.SRC_IN));
    }

    /* renamed from: a */
    public static void m987a(@NonNull Bitmap bitmap, @NonNull Bitmap bitmap2, Matrix matrix) {
        Lock lock = f2472e;
        lock.lock();
        try {
            Canvas canvas = new Canvas(bitmap2);
            canvas.drawBitmap(bitmap, matrix, f2468a);
            canvas.setBitmap(null);
            lock.unlock();
        } catch (Throwable th) {
            f2472e.unlock();
            throw th;
        }
    }

    /* renamed from: b */
    public static Bitmap m988b(@NonNull InterfaceC1614d interfaceC1614d, @NonNull Bitmap bitmap, int i2, int i3) {
        float width;
        float height;
        if (bitmap.getWidth() == i2 && bitmap.getHeight() == i3) {
            return bitmap;
        }
        Matrix matrix = new Matrix();
        float f2 = 0.0f;
        if (bitmap.getWidth() * i3 > bitmap.getHeight() * i2) {
            width = i3 / bitmap.getHeight();
            f2 = (i2 - (bitmap.getWidth() * width)) * 0.5f;
            height = 0.0f;
        } else {
            width = i2 / bitmap.getWidth();
            height = (i3 - (bitmap.getHeight() * width)) * 0.5f;
        }
        matrix.setScale(width, width);
        matrix.postTranslate((int) (f2 + 0.5f), (int) (height + 0.5f));
        Bitmap mo871e = interfaceC1614d.mo871e(i2, i3, m992f(bitmap));
        mo871e.setHasAlpha(bitmap.hasAlpha());
        m987a(bitmap, mo871e, matrix);
        return mo871e;
    }

    /* renamed from: c */
    public static Bitmap m989c(@NonNull InterfaceC1614d interfaceC1614d, @NonNull Bitmap bitmap, int i2, int i3) {
        if (bitmap.getWidth() == i2 && bitmap.getHeight() == i3) {
            Log.isLoggable("TransformationUtils", 2);
            return bitmap;
        }
        float min = Math.min(i2 / bitmap.getWidth(), i3 / bitmap.getHeight());
        int round = Math.round(bitmap.getWidth() * min);
        int round2 = Math.round(bitmap.getHeight() * min);
        if (bitmap.getWidth() == round && bitmap.getHeight() == round2) {
            Log.isLoggable("TransformationUtils", 2);
            return bitmap;
        }
        Bitmap mo871e = interfaceC1614d.mo871e((int) (bitmap.getWidth() * min), (int) (bitmap.getHeight() * min), m992f(bitmap));
        mo871e.setHasAlpha(bitmap.hasAlpha());
        if (Log.isLoggable("TransformationUtils", 2)) {
            bitmap.getWidth();
            bitmap.getHeight();
            mo871e.getWidth();
            mo871e.getHeight();
        }
        Matrix matrix = new Matrix();
        matrix.setScale(min, min);
        m987a(bitmap, mo871e, matrix);
        return mo871e;
    }

    /* renamed from: d */
    public static Bitmap m990d(@NonNull InterfaceC1614d interfaceC1614d, @NonNull Bitmap bitmap) {
        Bitmap.Config m991e = m991e(bitmap);
        if (m991e.equals(bitmap.getConfig())) {
            return bitmap;
        }
        Bitmap mo871e = interfaceC1614d.mo871e(bitmap.getWidth(), bitmap.getHeight(), m991e);
        new Canvas(mo871e).drawBitmap(bitmap, 0.0f, 0.0f, (Paint) null);
        return mo871e;
    }

    @NonNull
    /* renamed from: e */
    public static Bitmap.Config m991e(@NonNull Bitmap bitmap) {
        return (Build.VERSION.SDK_INT < 26 || !Bitmap.Config.RGBA_F16.equals(bitmap.getConfig())) ? Bitmap.Config.ARGB_8888 : Bitmap.Config.RGBA_F16;
    }

    @NonNull
    /* renamed from: f */
    public static Bitmap.Config m992f(@NonNull Bitmap bitmap) {
        return bitmap.getConfig() != null ? bitmap.getConfig() : Bitmap.Config.ARGB_8888;
    }
}
