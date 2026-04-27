package com.rnfs;

import android.os.AsyncTask;
import android.webkit.MimeTypeMap;
import java.util.concurrent.atomic.AtomicBoolean;

/* JADX INFO: loaded from: classes.dex */
public class i extends AsyncTask {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private g f8728a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private h f8729b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private AtomicBoolean f8730c = new AtomicBoolean(false);

    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() throws Throwable {
            try {
                i iVar = i.this;
                iVar.g(iVar.f8728a, i.this.f8729b);
                i.this.f8728a.f8721g.a(i.this.f8729b);
            } catch (Exception e3) {
                i.this.f8729b.f8726c = e3;
                i.this.f8728a.f8721g.a(i.this.f8729b);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:106:0x035e  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0363  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0368  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x036d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void g(com.rnfs.g r37, com.rnfs.h r38) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 881
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.rnfs.i.g(com.rnfs.g, com.rnfs.h):void");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // android.os.AsyncTask
    /* JADX INFO: renamed from: d, reason: merged with bridge method [inline-methods] */
    public h doInBackground(g... gVarArr) {
        this.f8728a = gVarArr[0];
        this.f8729b = new h();
        new Thread(new a()).start();
        return this.f8729b;
    }

    protected String e(String str) {
        String fileExtensionFromUrl = MimeTypeMap.getFileExtensionFromUrl(str);
        String mimeTypeFromExtension = fileExtensionFromUrl != null ? MimeTypeMap.getSingleton().getMimeTypeFromExtension(fileExtensionFromUrl.toLowerCase()) : null;
        return mimeTypeFromExtension == null ? "*/*" : mimeTypeFromExtension;
    }

    protected void f() {
        this.f8730c.set(true);
    }
}
