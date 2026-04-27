package androidx.profileinstaller;

import android.content.res.AssetManager;
import android.os.Build;
import androidx.profileinstaller.i;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final AssetManager f5206a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Executor f5207b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final i.c f5208c;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final File f5210e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final String f5211f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final String f5212g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final String f5213h;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private d[] f5215j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private byte[] f5216k;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f5214i = false;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final byte[] f5209d = d();

    public c(AssetManager assetManager, Executor executor, i.c cVar, String str, String str2, String str3, File file) {
        this.f5206a = assetManager;
        this.f5207b = executor;
        this.f5208c = cVar;
        this.f5211f = str;
        this.f5212g = str2;
        this.f5213h = str3;
        this.f5210e = file;
    }

    private c b(d[] dVarArr, byte[] bArr) {
        InputStream inputStreamH;
        try {
            inputStreamH = h(this.f5206a, this.f5213h);
        } catch (FileNotFoundException e3) {
            this.f5208c.b(9, e3);
        } catch (IOException e4) {
            this.f5208c.b(7, e4);
        } catch (IllegalStateException e5) {
            this.f5215j = null;
            this.f5208c.b(8, e5);
        }
        if (inputStreamH == null) {
            if (inputStreamH != null) {
                inputStreamH.close();
            }
            return null;
        }
        try {
            this.f5215j = n.q(inputStreamH, n.o(inputStreamH, n.f5244b), bArr, dVarArr);
            inputStreamH.close();
            return this;
        } catch (Throwable th) {
            try {
                inputStreamH.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    private void c() {
        if (!this.f5214i) {
            throw new IllegalStateException("This device doesn't support aot. Did you call deviceSupportsAotProfile()?");
        }
    }

    private static byte[] d() {
        int i3 = Build.VERSION.SDK_INT;
        if (i3 > 34) {
            return null;
        }
        switch (i3) {
        }
        return null;
    }

    private InputStream f(AssetManager assetManager) {
        try {
            return h(assetManager, this.f5212g);
        } catch (FileNotFoundException e3) {
            this.f5208c.b(6, e3);
            return null;
        } catch (IOException e4) {
            this.f5208c.b(7, e4);
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void g(int i3, Object obj) {
        this.f5208c.b(i3, obj);
    }

    private InputStream h(AssetManager assetManager, String str) {
        try {
            return assetManager.openFd(str).createInputStream();
        } catch (FileNotFoundException e3) {
            String message = e3.getMessage();
            if (message != null && message.contains("compressed")) {
                this.f5208c.a(5, null);
            }
            return null;
        }
    }

    private d[] j(InputStream inputStream) {
        try {
            try {
                try {
                    try {
                        d[] dVarArrW = n.w(inputStream, n.o(inputStream, n.f5243a), this.f5211f);
                        try {
                            inputStream.close();
                            return dVarArrW;
                        } catch (IOException e3) {
                            this.f5208c.b(7, e3);
                            return dVarArrW;
                        }
                    } catch (IOException e4) {
                        this.f5208c.b(7, e4);
                        return null;
                    }
                } catch (IllegalStateException e5) {
                    this.f5208c.b(8, e5);
                    inputStream.close();
                    return null;
                }
            } catch (IOException e6) {
                this.f5208c.b(7, e6);
                inputStream.close();
                return null;
            }
        } catch (Throwable th) {
            try {
                inputStream.close();
            } catch (IOException e7) {
                this.f5208c.b(7, e7);
            }
            throw th;
        }
    }

    private static boolean k() {
        int i3 = Build.VERSION.SDK_INT;
        if (i3 > 34) {
            return false;
        }
        if (i3 != 24 && i3 != 25) {
            switch (i3) {
            }
            return false;
        }
        return true;
    }

    private void l(final int i3, final Object obj) {
        this.f5207b.execute(new Runnable() { // from class: androidx.profileinstaller.b
            @Override // java.lang.Runnable
            public final void run() {
                this.f5203b.g(i3, obj);
            }
        });
    }

    public boolean e() {
        if (this.f5209d == null) {
            l(3, Integer.valueOf(Build.VERSION.SDK_INT));
            return false;
        }
        if (!this.f5210e.exists()) {
            try {
                this.f5210e.createNewFile();
            } catch (IOException unused) {
                l(4, null);
                return false;
            }
        } else if (!this.f5210e.canWrite()) {
            l(4, null);
            return false;
        }
        this.f5214i = true;
        return true;
    }

    public c i() {
        c cVarB;
        c();
        if (this.f5209d == null) {
            return this;
        }
        InputStream inputStreamF = f(this.f5206a);
        if (inputStreamF != null) {
            this.f5215j = j(inputStreamF);
        }
        d[] dVarArr = this.f5215j;
        return (dVarArr == null || !k() || (cVarB = b(dVarArr, this.f5209d)) == null) ? this : cVarB;
    }

    public c m() {
        ByteArrayOutputStream byteArrayOutputStream;
        d[] dVarArr = this.f5215j;
        byte[] bArr = this.f5209d;
        if (dVarArr != null && bArr != null) {
            c();
            try {
                byteArrayOutputStream = new ByteArrayOutputStream();
                try {
                    n.E(byteArrayOutputStream, bArr);
                } catch (Throwable th) {
                    try {
                        byteArrayOutputStream.close();
                    } catch (Throwable th2) {
                        th.addSuppressed(th2);
                    }
                    throw th;
                }
            } catch (IOException e3) {
                this.f5208c.b(7, e3);
            } catch (IllegalStateException e4) {
                this.f5208c.b(8, e4);
            }
            if (!n.B(byteArrayOutputStream, bArr, dVarArr)) {
                this.f5208c.b(5, null);
                this.f5215j = null;
                byteArrayOutputStream.close();
                return this;
            }
            this.f5216k = byteArrayOutputStream.toByteArray();
            byteArrayOutputStream.close();
            this.f5215j = null;
        }
        return this;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public boolean n() {
        byte[] bArr = this.f5216k;
        if (bArr == null) {
            return false;
        }
        c();
        try {
            try {
                ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
                try {
                    FileOutputStream fileOutputStream = new FileOutputStream(this.f5210e);
                    try {
                        e.l(byteArrayInputStream, fileOutputStream);
                        l(1, null);
                        fileOutputStream.close();
                        byteArrayInputStream.close();
                        return true;
                    } finally {
                    }
                } catch (Throwable th) {
                    try {
                        byteArrayInputStream.close();
                    } catch (Throwable th2) {
                        th.addSuppressed(th2);
                    }
                    throw th;
                }
            } finally {
                this.f5216k = null;
                this.f5215j = null;
            }
        } catch (FileNotFoundException e3) {
            l(6, e3);
            return false;
        } catch (IOException e4) {
            l(7, e4);
            return false;
        }
    }
}
