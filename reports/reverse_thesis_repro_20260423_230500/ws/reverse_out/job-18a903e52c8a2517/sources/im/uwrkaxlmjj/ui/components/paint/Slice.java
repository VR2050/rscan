package im.uwrkaxlmjj.ui.components.paint;

import android.graphics.RectF;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.FileLog;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.util.zip.Deflater;

/* JADX INFO: loaded from: classes5.dex */
public class Slice {
    private RectF bounds;
    private File file;

    public Slice(ByteBuffer data, RectF rect, DispatchQueue queue) {
        this.bounds = rect;
        try {
            File outputDir = ApplicationLoader.applicationContext.getCacheDir();
            this.file = File.createTempFile("paint", ".bin", outputDir);
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (this.file == null) {
            return;
        }
        storeData(data);
    }

    public void cleanResources() {
        File file = this.file;
        if (file != null) {
            file.delete();
            this.file = null;
        }
    }

    private void storeData(ByteBuffer data) {
        try {
            byte[] input = data.array();
            FileOutputStream fos = new FileOutputStream(this.file);
            Deflater deflater = new Deflater(1, true);
            deflater.setInput(input, data.arrayOffset(), data.remaining());
            deflater.finish();
            byte[] buf = new byte[1024];
            while (!deflater.finished()) {
                int byteCount = deflater.deflate(buf);
                fos.write(buf, 0, byteCount);
            }
            deflater.end();
            fos.close();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x004c A[Catch: Exception -> 0x0054, TRY_LEAVE, TryCatch #0 {Exception -> 0x0054, blocks: (B:3:0x0002, B:4:0x0018, B:6:0x0020, B:7:0x0023, B:9:0x002b, B:10:0x002f, B:12:0x0036, B:14:0x004c), top: B:21:0x0002 }] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0036 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:24:0x002f A[EDGE_INSN: B:24:0x002f->B:10:0x002f BREAK  A[LOOP:1: B:7:0x0023->B:9:0x002b], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:6:0x0020 A[Catch: Exception -> 0x0054, TryCatch #0 {Exception -> 0x0054, blocks: (B:3:0x0002, B:4:0x0018, B:6:0x0020, B:7:0x0023, B:9:0x002b, B:10:0x002f, B:12:0x0036, B:14:0x004c), top: B:21:0x0002 }] */
    /* JADX WARN: Removed duplicated region for block: B:9:0x002b A[Catch: Exception -> 0x0054, LOOP:1: B:7:0x0023->B:9:0x002b, LOOP_END, TryCatch #0 {Exception -> 0x0054, blocks: (B:3:0x0002, B:4:0x0018, B:6:0x0020, B:7:0x0023, B:9:0x002b, B:10:0x002f, B:12:0x0036, B:14:0x004c), top: B:21:0x0002 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.nio.ByteBuffer getData() {
        /*
            r9 = this;
            r0 = 1024(0x400, float:1.435E-42)
            byte[] r1 = new byte[r0]     // Catch: java.lang.Exception -> L54
            byte[] r0 = new byte[r0]     // Catch: java.lang.Exception -> L54
            java.io.FileInputStream r2 = new java.io.FileInputStream     // Catch: java.lang.Exception -> L54
            java.io.File r3 = r9.file     // Catch: java.lang.Exception -> L54
            r2.<init>(r3)     // Catch: java.lang.Exception -> L54
            java.io.ByteArrayOutputStream r3 = new java.io.ByteArrayOutputStream     // Catch: java.lang.Exception -> L54
            r3.<init>()     // Catch: java.lang.Exception -> L54
            java.util.zip.Inflater r4 = new java.util.zip.Inflater     // Catch: java.lang.Exception -> L54
            r5 = 1
            r4.<init>(r5)     // Catch: java.lang.Exception -> L54
        L18:
            int r5 = r2.read(r1)     // Catch: java.lang.Exception -> L54
            r6 = -1
            r7 = 0
            if (r5 == r6) goto L23
            r4.setInput(r1, r7, r5)     // Catch: java.lang.Exception -> L54
        L23:
            int r6 = r0.length     // Catch: java.lang.Exception -> L54
            int r6 = r4.inflate(r0, r7, r6)     // Catch: java.lang.Exception -> L54
            r8 = r6
            if (r6 == 0) goto L2f
            r3.write(r0, r7, r8)     // Catch: java.lang.Exception -> L54
            goto L23
        L2f:
            boolean r6 = r4.finished()     // Catch: java.lang.Exception -> L54
            if (r6 == 0) goto L4c
        L36:
            r4.end()     // Catch: java.lang.Exception -> L54
            byte[] r5 = r3.toByteArray()     // Catch: java.lang.Exception -> L54
            int r6 = r3.size()     // Catch: java.lang.Exception -> L54
            java.nio.ByteBuffer r5 = java.nio.ByteBuffer.wrap(r5, r7, r6)     // Catch: java.lang.Exception -> L54
            r3.close()     // Catch: java.lang.Exception -> L54
            r2.close()     // Catch: java.lang.Exception -> L54
            return r5
        L4c:
            boolean r6 = r4.needsInput()     // Catch: java.lang.Exception -> L54
            if (r6 == 0) goto L53
            goto L18
        L53:
            goto L18
        L54:
            r0 = move-exception
            im.uwrkaxlmjj.messenger.FileLog.e(r0)
            r0 = 0
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.paint.Slice.getData():java.nio.ByteBuffer");
    }

    public int getX() {
        return (int) this.bounds.left;
    }

    public int getY() {
        return (int) this.bounds.top;
    }

    public int getWidth() {
        return (int) this.bounds.width();
    }

    public int getHeight() {
        return (int) this.bounds.height();
    }

    public RectF getBounds() {
        return new RectF(this.bounds);
    }
}
