package p005b.p172h.p173a.p174r;

import android.text.TextUtils;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p172h.p173a.C1817f;

/* renamed from: b.h.a.r.e */
/* loaded from: classes.dex */
public abstract class AbstractC1833e implements InterfaceC1829a {

    /* renamed from: a */
    public final ExecutorService f2836a = Executors.newSingleThreadExecutor();

    /* renamed from: b.h.a.r.e$a */
    public class a implements Callable<Void> {

        /* renamed from: a */
        public final File f2837a;

        public a(File file) {
            this.f2837a = file;
        }

        @Override // java.util.concurrent.Callable
        public Void call() {
            AbstractC1833e abstractC1833e = AbstractC1833e.this;
            File file = this.f2837a;
            Objects.requireNonNull(abstractC1833e);
            long j2 = 0;
            if (file.exists()) {
                long currentTimeMillis = System.currentTimeMillis();
                if (!file.setLastModified(currentTimeMillis)) {
                    long length = file.length();
                    if (length != 0) {
                        RandomAccessFile randomAccessFile = new RandomAccessFile(file, "rwd");
                        long j3 = length - 1;
                        randomAccessFile.seek(j3);
                        byte readByte = randomAccessFile.readByte();
                        randomAccessFile.seek(j3);
                        randomAccessFile.write(readByte);
                        randomAccessFile.close();
                    } else if (!file.delete() || !file.createNewFile()) {
                        throw new IOException(C1499a.m634t("Error recreate zero-size file ", file));
                    }
                    if (file.lastModified() < currentTimeMillis) {
                        C1817f.m1165b("Last modified date {} is not set for file {}", new Date(file.lastModified()).toString() + "\n" + file.getAbsolutePath());
                    }
                }
            }
            File parentFile = file.getParentFile();
            List<File> linkedList = new LinkedList();
            File[] listFiles = parentFile.listFiles();
            if (listFiles != null) {
                linkedList = Arrays.asList(listFiles);
                Collections.sort(linkedList, new C1832d(null));
            }
            Iterator it = linkedList.iterator();
            while (it.hasNext()) {
                j2 += ((File) it.next()).length();
            }
            linkedList.size();
            for (File file2 : linkedList) {
                if (!(j2 <= ((C1835g) abstractC1833e).f2839b)) {
                    long length2 = file2.length();
                    if (file2.delete()) {
                        j2 -= length2;
                        String str = "Cache file " + file2 + " is deleted because it exceeds cache limit";
                        if (str != null) {
                            TextUtils.isEmpty(str);
                        }
                    } else {
                        TextUtils.isEmpty("Error deleting file " + file2 + " for trimming cache");
                    }
                }
            }
            return null;
        }
    }

    /* renamed from: a */
    public void m1188a(File file) {
        this.f2836a.submit(new a(file));
    }
}
