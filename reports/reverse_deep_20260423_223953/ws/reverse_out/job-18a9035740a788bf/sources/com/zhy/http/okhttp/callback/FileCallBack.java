package com.zhy.http.okhttp.callback;

import com.zhy.http.okhttp.OkHttpUtils;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import okhttp3.Response;

/* JADX INFO: loaded from: classes3.dex */
public abstract class FileCallBack extends Callback<File> {
    private String destFileDir;
    private String destFileName;

    public FileCallBack(String destFileDir, String destFileName) {
        this.destFileDir = destFileDir;
        this.destFileName = destFileName;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.zhy.http.okhttp.callback.Callback
    public File parseNetworkResponse(Response response, int id) throws Exception {
        return saveFile(response, id);
    }

    public File saveFile(Response response, final int id) throws Throwable {
        Throwable th;
        InputStream is;
        final long total;
        File file;
        FileOutputStream fos;
        int len;
        long sum;
        InputStream is2 = null;
        byte[] buf = new byte[2048];
        FileOutputStream fos2 = null;
        try {
            is = response.body().byteStream();
            try {
                total = response.body().contentLength();
                File dir = new File(this.destFileDir);
                if (!dir.exists()) {
                    dir.mkdirs();
                }
                file = new File(dir, this.destFileName);
                fos = new FileOutputStream(file);
                len = 0;
                sum = 0;
            } catch (Throwable th2) {
                th = th2;
                is2 = is;
            }
        } catch (Throwable th3) {
            th = th3;
        }
        while (true) {
            try {
                int len2 = is.read(buf);
                if (len2 == -1) {
                    break;
                }
                final long sum2 = sum + ((long) len2);
                try {
                    fos.write(buf, 0, len2);
                    OkHttpUtils.getInstance().getDelivery().execute(new Runnable() { // from class: com.zhy.http.okhttp.callback.FileCallBack.1
                        @Override // java.lang.Runnable
                        public void run() {
                            long j = total;
                            FileCallBack.this.inProgress((sum2 * 1.0f) / j, j, id);
                        }
                    });
                    len = len2;
                    sum = sum2;
                } catch (Throwable th4) {
                    th = th4;
                    is2 = is;
                    fos2 = fos;
                }
                th = th4;
                is2 = is;
                fos2 = fos;
            } catch (Throwable th5) {
                th = th5;
                is2 = is;
                fos2 = fos;
            }
            try {
                response.body().close();
                if (is2 != null) {
                    is2.close();
                }
            } catch (IOException e) {
            }
            if (fos2 == null) {
                throw th;
            }
            try {
                fos2.close();
                throw th;
            } catch (IOException e2) {
                throw th;
            }
        }
        fos.flush();
        try {
            response.body().close();
            if (is != null) {
                is.close();
            }
        } catch (IOException e3) {
        }
        try {
            fos.close();
        } catch (IOException e4) {
        }
        return file;
    }
}
