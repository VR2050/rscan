package c0;

import X.p;
import android.os.Environment;
import android.os.StatFs;
import android.os.SystemClock;
import java.io.File;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/* JADX INFO: renamed from: c0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0326a {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static C0326a f5415h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final long f5416i = TimeUnit.MINUTES.toMillis(2);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private volatile File f5418b;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private volatile File f5420d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private long f5421e;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private volatile StatFs f5417a = null;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private volatile StatFs f5419c = null;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private volatile boolean f5423g = false;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Lock f5422f = new ReentrantLock();

    /* JADX INFO: renamed from: c0.a$a, reason: collision with other inner class name */
    public enum EnumC0086a {
        INTERNAL,
        EXTERNAL
    }

    protected C0326a() {
    }

    protected static StatFs a(String str) {
        return new StatFs(str);
    }

    private void b() {
        if (this.f5423g) {
            return;
        }
        this.f5422f.lock();
        try {
            if (!this.f5423g) {
                this.f5418b = Environment.getDataDirectory();
                this.f5420d = Environment.getExternalStorageDirectory();
                g();
                this.f5423g = true;
            }
        } finally {
            this.f5422f.unlock();
        }
    }

    public static synchronized C0326a d() {
        try {
            if (f5415h == null) {
                f5415h = new C0326a();
            }
        } catch (Throwable th) {
            throw th;
        }
        return f5415h;
    }

    private void e() {
        if (this.f5422f.tryLock()) {
            try {
                if (SystemClock.uptimeMillis() - this.f5421e > f5416i) {
                    g();
                }
            } finally {
                this.f5422f.unlock();
            }
        }
    }

    private void g() {
        this.f5417a = h(this.f5417a, this.f5418b);
        this.f5419c = h(this.f5419c, this.f5420d);
        this.f5421e = SystemClock.uptimeMillis();
    }

    private StatFs h(StatFs statFs, File file) {
        StatFs statFs2 = null;
        if (file == null || !file.exists()) {
            return null;
        }
        try {
            if (statFs == null) {
                statFs = a(file.getAbsolutePath());
            } else {
                statFs.restat(file.getAbsolutePath());
            }
            statFs2 = statFs;
            return statFs2;
        } catch (IllegalArgumentException unused) {
            return statFs2;
        } catch (Throwable th) {
            throw p.a(th);
        }
    }

    public long c(EnumC0086a enumC0086a) {
        b();
        e();
        StatFs statFs = enumC0086a == EnumC0086a.INTERNAL ? this.f5417a : this.f5419c;
        if (statFs != null) {
            return statFs.getBlockSizeLong() * statFs.getAvailableBlocksLong();
        }
        return 0L;
    }

    public boolean f(EnumC0086a enumC0086a, long j3) {
        b();
        long jC = c(enumC0086a);
        return jC <= 0 || jC < j3;
    }
}
