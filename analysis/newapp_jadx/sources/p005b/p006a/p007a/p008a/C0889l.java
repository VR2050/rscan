package p005b.p006a.p007a.p008a;

import android.content.Context;
import android.os.Looper;
import android.os.Process;
import com.jbzd.media.movecartoons.bean.request.RequestSystemInfoBody;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.Thread;
import java.util.HashMap;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.p472io.TextStreamsKt;
import kotlin.text.Charsets;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.a.a.a.l */
/* loaded from: classes2.dex */
public final class C0889l implements Thread.UncaughtExceptionHandler {

    /* renamed from: a */
    @NotNull
    public final Context f338a;

    /* renamed from: b */
    @NotNull
    public final Lazy f339b;

    /* renamed from: b.a.a.a.l$a */
    public static final class a extends Lambda implements Function0<Thread.UncaughtExceptionHandler> {

        /* renamed from: c */
        public static final a f340c = new a();

        public a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public Thread.UncaughtExceptionHandler invoke() {
            return Thread.getDefaultUncaughtExceptionHandler();
        }
    }

    public C0889l(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.f338a = context;
        this.f339b = LazyKt__LazyJVMKt.lazy(a.f340c);
        Thread.setDefaultUncaughtExceptionHandler(this);
        File externalFilesDir = context.getExternalFilesDir(null);
        File file = new File(Intrinsics.stringPlus(externalFilesDir != null ? externalFilesDir.getPath() : null, "/crash_logInfo/"));
        if (file.exists()) {
            File[] listFiles = file.listFiles();
            Intrinsics.checkNotNullExpressionValue(listFiles, "fl.listFiles()");
            int i2 = 0;
            if (!(listFiles.length == 0)) {
                File[] listFiles2 = file.listFiles();
                Intrinsics.checkNotNullExpressionValue(listFiles2, "fl.listFiles()");
                int length = listFiles2.length;
                while (i2 < length) {
                    File f2 = listFiles2[i2];
                    i2++;
                    HashMap hashMap = new HashMap();
                    Intrinsics.checkNotNullExpressionValue(f2, "f");
                    BufferedReader bufferedReader = new BufferedReader(new FileReader(f2));
                    String readText = TextStreamsKt.readText(bufferedReader);
                    bufferedReader.close();
                    hashMap.put("content", readText);
                    C0917a.m221e(C0917a.f372a, "system/reportError", String.class, hashMap, new C0890m(f2), null, true, false, null, false, 400);
                }
            }
        }
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public void uncaughtException(@Nullable Thread thread, @Nullable Throwable th) {
        boolean z;
        if (th == null) {
            z = false;
        } else {
            new Thread(new Runnable() { // from class: b.a.a.a.f
                @Override // java.lang.Runnable
                public final void run() {
                    Looper.prepare();
                    C2354n.m2525w0("很抱歉，程序出现异常，即将退出");
                    Looper.loop();
                }
            }).start();
            String deviceInfoData = RequestSystemInfoBody.getDeviceInfoData();
            StringWriter stringWriter = new StringWriter();
            stringWriter.append((CharSequence) ("230113;" + ((Object) deviceInfoData) + '\n'));
            PrintWriter printWriter = new PrintWriter(stringWriter);
            th.printStackTrace(printWriter);
            for (Throwable cause = th.getCause(); cause != null; cause = cause.getCause()) {
                cause.printStackTrace(printWriter);
            }
            printWriter.close();
            String m631q = C1499a.m631q("crash-", System.currentTimeMillis(), ".log");
            File externalFilesDir = this.f338a.getExternalFilesDir(null);
            String stringPlus = Intrinsics.stringPlus(externalFilesDir != null ? externalFilesDir.getPath() : null, "/crash_logInfo/");
            File file = new File(stringPlus);
            if (!file.exists()) {
                file.mkdirs();
            }
            try {
                FileOutputStream fileOutputStream = new FileOutputStream(Intrinsics.stringPlus(stringPlus, m631q));
                byte[] bytes = stringWriter.toString().getBytes(Charsets.UTF_8);
                Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
                fileOutputStream.write(bytes);
                fileOutputStream.close();
            } catch (FileNotFoundException e2) {
                e2.printStackTrace();
            } catch (IOException e3) {
                e3.printStackTrace();
            }
            z = true;
        }
        if (!z && ((Thread.UncaughtExceptionHandler) this.f339b.getValue()) != null) {
            ((Thread.UncaughtExceptionHandler) this.f339b.getValue()).uncaughtException(thread, th);
            return;
        }
        try {
            Thread.sleep(3000L);
        } catch (InterruptedException e4) {
            e4.printStackTrace();
        }
        try {
            System.exit(0);
            throw new RuntimeException("System.exit returned normally, while it was supposed to halt JVM.");
        } catch (Exception e5) {
            e5.printStackTrace();
            try {
                Process.killProcess(Process.myPid());
            } catch (Exception e6) {
                e6.printStackTrace();
            }
        }
    }
}
