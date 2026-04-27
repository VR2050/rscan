package androidx.profileinstaller;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Objects;

/* JADX INFO: loaded from: classes.dex */
public abstract class o {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final androidx.concurrent.futures.c f5245a = androidx.concurrent.futures.c.o();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final Object f5246b = new Object();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static c f5247c = null;

    private static class a {
        static PackageInfo a(PackageManager packageManager, Context context) {
            return packageManager.getPackageInfo(context.getPackageName(), PackageManager.PackageInfoFlags.of(0L));
        }
    }

    static class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final int f5248a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final int f5249b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final long f5250c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final long f5251d;

        b(int i3, int i4, long j3, long j4) {
            this.f5248a = i3;
            this.f5249b = i4;
            this.f5250c = j3;
            this.f5251d = j4;
        }

        static b a(File file) throws IOException {
            DataInputStream dataInputStream = new DataInputStream(new FileInputStream(file));
            try {
                b bVar = new b(dataInputStream.readInt(), dataInputStream.readInt(), dataInputStream.readLong(), dataInputStream.readLong());
                dataInputStream.close();
                return bVar;
            } catch (Throwable th) {
                try {
                    dataInputStream.close();
                } catch (Throwable th2) {
                    th.addSuppressed(th2);
                }
                throw th;
            }
        }

        void b(File file) throws IOException {
            file.delete();
            DataOutputStream dataOutputStream = new DataOutputStream(new FileOutputStream(file));
            try {
                dataOutputStream.writeInt(this.f5248a);
                dataOutputStream.writeInt(this.f5249b);
                dataOutputStream.writeLong(this.f5250c);
                dataOutputStream.writeLong(this.f5251d);
                dataOutputStream.close();
            } catch (Throwable th) {
                try {
                    dataOutputStream.close();
                } catch (Throwable th2) {
                    th.addSuppressed(th2);
                }
                throw th;
            }
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || !(obj instanceof b)) {
                return false;
            }
            b bVar = (b) obj;
            return this.f5249b == bVar.f5249b && this.f5250c == bVar.f5250c && this.f5248a == bVar.f5248a && this.f5251d == bVar.f5251d;
        }

        public int hashCode() {
            return Objects.hash(Integer.valueOf(this.f5249b), Long.valueOf(this.f5250c), Integer.valueOf(this.f5248a), Long.valueOf(this.f5251d));
        }
    }

    public static class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final int f5252a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final boolean f5253b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final boolean f5254c;

        c(int i3, boolean z3, boolean z4) {
            this.f5252a = i3;
            this.f5254c = z4;
            this.f5253b = z3;
        }
    }

    private static long a(Context context) {
        PackageManager packageManager = context.getApplicationContext().getPackageManager();
        return Build.VERSION.SDK_INT >= 33 ? a.a(packageManager, context).lastUpdateTime : packageManager.getPackageInfo(context.getPackageName(), 0).lastUpdateTime;
    }

    private static c b(int i3, boolean z3, boolean z4) {
        c cVar = new c(i3, z3, z4);
        f5247c = cVar;
        f5245a.m(cVar);
        return f5247c;
    }

    static c c(Context context, boolean z3) {
        b bVarA;
        int i3;
        c cVar;
        if (!z3 && (cVar = f5247c) != null) {
            return cVar;
        }
        synchronized (f5246b) {
            if (!z3) {
                try {
                    c cVar2 = f5247c;
                    if (cVar2 != null) {
                        return cVar2;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
            int i4 = Build.VERSION.SDK_INT;
            int i5 = 0;
            if (i4 >= 28 && i4 != 30) {
                File file = new File(new File("/data/misc/profiles/ref/", context.getPackageName()), "primary.prof");
                long length = file.length();
                boolean z4 = file.exists() && length > 0;
                File file2 = new File(new File("/data/misc/profiles/cur/0/", context.getPackageName()), "primary.prof");
                long length2 = file2.length();
                boolean z5 = file2.exists() && length2 > 0;
                try {
                    long jA = a(context);
                    File file3 = new File(context.getFilesDir(), "profileInstalled");
                    if (file3.exists()) {
                        try {
                            bVarA = b.a(file3);
                        } catch (IOException unused) {
                            return b(131072, z4, z5);
                        }
                    } else {
                        bVarA = null;
                    }
                    if (bVarA != null && bVarA.f5250c == jA && (i3 = bVarA.f5249b) != 2) {
                        i5 = i3;
                    } else if (z4) {
                        i5 = 1;
                    } else if (z5) {
                        i5 = 2;
                    }
                    if (z3 && z5 && i5 != 1) {
                        i5 = 2;
                    }
                    if (bVarA != null && bVarA.f5249b == 2 && i5 == 1 && length < bVarA.f5251d) {
                        i5 = 3;
                    }
                    b bVar = new b(1, i5, jA, length2);
                    if (bVarA == null || !bVarA.equals(bVar)) {
                        try {
                            bVar.b(file3);
                        } catch (IOException unused2) {
                            i5 = 196608;
                        }
                    }
                    return b(i5, z4, z5);
                } catch (PackageManager.NameNotFoundException unused3) {
                    return b(65536, z4, z5);
                }
            }
            return b(262144, false, false);
        }
    }
}
