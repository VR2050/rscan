package com.rnfs;

import android.os.AsyncTask;
import com.rnfs.a;
import java.net.HttpURLConnection;
import java.util.concurrent.atomic.AtomicBoolean;

/* JADX INFO: loaded from: classes.dex */
public class c extends AsyncTask {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private com.rnfs.a f8710a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private AtomicBoolean f8711b = new AtomicBoolean(false);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    b f8712c;

    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() throws Throwable {
            try {
                c cVar = c.this;
                cVar.d(cVar.f8710a, c.this.f8712c);
                c.this.f8710a.f8704h.a(c.this.f8712c);
            } catch (Exception e3) {
                c cVar2 = c.this;
                cVar2.f8712c.f8709c = e3;
                cVar2.f8710a.f8704h.a(c.this.f8712c);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:101:0x01fb  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0200  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0205  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x01de  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x01e8  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x01ed  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void d(com.rnfs.a r29, com.rnfs.b r30) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 521
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.rnfs.c.d(com.rnfs.a, com.rnfs.b):void");
    }

    private long e(HttpURLConnection httpURLConnection) {
        return httpURLConnection.getContentLengthLong();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // android.os.AsyncTask
    /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
    public b doInBackground(com.rnfs.a... aVarArr) {
        this.f8710a = aVarArr[0];
        this.f8712c = new b();
        new Thread(new a()).start();
        return this.f8712c;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // android.os.AsyncTask
    /* JADX INFO: renamed from: f, reason: merged with bridge method [inline-methods] */
    public void onProgressUpdate(long[]... jArr) {
        super.onProgressUpdate(jArr);
        a.b bVar = this.f8710a.f8706j;
        if (bVar != null) {
            long[] jArr2 = jArr[0];
            bVar.a(jArr2[0], jArr2[1]);
        }
    }

    protected void g() {
        this.f8711b.set(true);
    }
}
