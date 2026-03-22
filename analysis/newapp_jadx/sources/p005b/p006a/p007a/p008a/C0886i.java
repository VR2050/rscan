package p005b.p006a.p007a.p008a;

import android.os.Build;
import android.text.TextUtils;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.Thread;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p472io.FilesKt__FileReadWriteKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import p005b.p139f.p140a.p142b.C1535e;
import p005b.p199l.p258c.C2480j;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p458k.C4375d0;
import p458k.C4379f0;
import p458k.C4381g0;
import p458k.C4486w;
import p458k.C4489z;

/* renamed from: b.a.a.a.i */
/* loaded from: classes2.dex */
public final class C0886i implements Thread.UncaughtExceptionHandler {

    /* renamed from: a */
    @NotNull
    public final SimpleDateFormat f331a = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss");

    /* renamed from: b */
    @NotNull
    public final String f332b;

    /* renamed from: c */
    @NotNull
    public final String f333c;

    /* renamed from: d */
    @NotNull
    public final String f334d;

    /* renamed from: e */
    public final ExecutorService f335e;

    /* renamed from: f */
    @NotNull
    public final C4375d0 f336f;

    public C0886i() {
        MyApp myApp = MyApp.f9891f;
        UserInfoBean userInfoBean = MyApp.f9892g;
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        File externalFilesDir = applicationC2828a.getExternalFilesDir(null);
        String stringPlus = Intrinsics.stringPlus(externalFilesDir != null ? externalFilesDir.getPath() : null, "/crash_logInfo");
        this.f332b = stringPlus;
        this.f333c = "Crash_Reports";
        this.f334d = stringPlus + "/Crash_Reports";
        new C2480j();
        ExecutorService newSingleThreadExecutor = Executors.newSingleThreadExecutor();
        this.f335e = newSingleThreadExecutor;
        this.f336f = new C4375d0(new C4375d0.a());
        newSingleThreadExecutor.execute(new Runnable() { // from class: b.a.a.a.b
            @Override // java.lang.Runnable
            public final void run() {
                C0886i this$0 = C0886i.this;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Objects.requireNonNull(this$0);
                try {
                    File file = new File(this$0.f334d);
                    if (file.exists()) {
                        String readText$default = FilesKt__FileReadWriteKt.readText$default(file, null, 1, null);
                        if (TextUtils.isEmpty(StringsKt__StringsKt.trim((CharSequence) readText$default).toString())) {
                            return;
                        }
                        ArrayList arrayList = new ArrayList();
                        ArrayList arrayList2 = new ArrayList();
                        Intrinsics.checkParameterIsNotNull("chat_id", "name");
                        Intrinsics.checkParameterIsNotNull("-824502922", "value");
                        C4489z.b bVar = C4489z.f12044b;
                        arrayList.add(C4489z.b.m5303a(bVar, "chat_id", 0, 0, " \"':;<=>@[]^`{}|/\\?#&!$(),~", false, false, true, false, null, 91));
                        arrayList2.add(C4489z.b.m5303a(bVar, "-824502922", 0, 0, " \"':;<=>@[]^`{}|/\\?#&!$(),~", false, false, true, false, null, 91));
                        String value = Intrinsics.stringPlus("麝香漫画:", readText$default);
                        Intrinsics.checkParameterIsNotNull("text", "name");
                        Intrinsics.checkParameterIsNotNull(value, "value");
                        arrayList.add(C4489z.b.m5303a(bVar, "text", 0, 0, " \"':;<=>@[]^`{}|/\\?#&!$(),~", false, false, true, false, null, 91));
                        arrayList2.add(C4489z.b.m5303a(bVar, value, 0, 0, " \"':;<=>@[]^`{}|/\\?#&!$(),~", false, false, true, false, null, 91));
                        C4486w c4486w = new C4486w(arrayList, arrayList2);
                        C4375d0 c4375d0 = this$0.f336f;
                        C4381g0.a aVar = new C4381g0.a();
                        aVar.m4978h("https://api.telegram.org/bot6086117813:AAFwiL2Rn_qZbWa_a6DkegGeAx1gIJorQzA/sendMessage");
                        aVar.m4975e("POST", c4486w);
                        ((C4379f0) c4375d0.mo4955a(aVar.m4972b())).m4965a();
                    }
                } catch (Exception e2) {
                    C1535e.m691d(6, C1535e.f1719d.m694a(), Intrinsics.stringPlus("--appera error: ", e2.getMessage()));
                }
            }
        });
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public void uncaughtException(@NotNull Thread t, @NotNull Throwable e2) {
        Intrinsics.checkNotNullParameter(t, "t");
        Intrinsics.checkNotNullParameter(e2, "e");
        try {
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            e2.printStackTrace(printWriter);
            StringBuilder sb = new StringBuilder();
            sb.append("************* Log Head ****************\nnickname      :");
            MyApp myApp = MyApp.f9891f;
            UserInfoBean userInfoBean = MyApp.f9892g;
            Intrinsics.checkNotNull(userInfoBean);
            sb.append((Object) userInfoBean.nickname);
            sb.append("\nid      :");
            sb.append((Object) MyApp.f9892g.username);
            sb.append("\nname      :");
            sb.append((Object) MyApp.f9892g.nickname);
            sb.append("\nvip_expire      :");
            sb.append((Object) MyApp.f9892g.is_vip);
            sb.append("\nTime Of Crash      : ");
            sb.append((Object) this.f331a.format(new Date(System.currentTimeMillis())));
            sb.append("\nDevice Manufacturer: ");
            sb.append((Object) Build.MANUFACTURER);
            sb.append("\nDevice Model       : ");
            sb.append((Object) Build.MODEL);
            sb.append("\nAndroid Version    : ");
            sb.append((Object) Build.VERSION.RELEASE);
            sb.append("\nAndroid SDK        : ");
            sb.append(Build.VERSION.SDK_INT);
            sb.append("\nApp VersionName    : 3.91\nApp VersionCode    : 39\n************* Log Head ****************\n\n");
            String sb2 = sb.toString();
            StringBuffer stringBuffer = new StringBuffer();
            stringBuffer.append(sb2);
            stringBuffer.append(stringWriter.toString());
            printWriter.close();
            if (this.f334d != null) {
                String stringBuffer2 = stringBuffer.toString();
                Intrinsics.checkNotNullExpressionValue(stringBuffer2, "sb.toString()");
                try {
                    File file = new File(this.f332b);
                    if (!file.exists()) {
                        file.mkdirs();
                    }
                    File file2 = new File(this.f334d);
                    if (!file2.exists()) {
                        file2.createNewFile();
                    }
                    FilesKt__FileReadWriteKt.writeText$default(file2, stringBuffer2, null, 2, null);
                } catch (Exception e3) {
                    e3.getMessage();
                }
            }
        } catch (Throwable th) {
            Intrinsics.stringPlus("--appear error: ", th.getLocalizedMessage());
        }
    }
}
