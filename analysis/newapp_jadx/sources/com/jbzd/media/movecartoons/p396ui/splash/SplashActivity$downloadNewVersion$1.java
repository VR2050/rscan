package com.jbzd.media.movecartoons.p396ui.splash;

import android.app.ProgressDialog;
import com.jbzd.media.movecartoons.MyApp;
import java.io.File;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import me.jessyan.progressmanager.body.ProgressInfo;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2859c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001f\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0004*\u0001\u0000\b\n\u0018\u00002\u00020\u0001J\u0019\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\u0007\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\t\u0010\bJ\u0017\u0010\f\u001a\u00020\u00042\u0006\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\f\u0010\r¨\u0006\u000e"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/splash/SplashActivity$downloadNewVersion$1", "Lb/w/b/d/c$c;", "Lme/jessyan/progressmanager/body/ProgressInfo;", "progress", "", "onDownloading", "(Lme/jessyan/progressmanager/body/ProgressInfo;)V", "onDownloadFailed", "()V", "onDownloadSuccess", "", "data", "onDownloadSuccessData", "(Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SplashActivity$downloadNewVersion$1 implements C2859c.c {
    public final /* synthetic */ ProgressDialog $dialog;
    public final /* synthetic */ SplashActivity this$0;

    public SplashActivity$downloadNewVersion$1(ProgressDialog progressDialog, SplashActivity splashActivity) {
        this.$dialog = progressDialog;
        this.this$0 = splashActivity;
    }

    @Override // p005b.p327w.p330b.p337d.C2859c.c
    public void onDownloadFailed() {
        this.this$0.runOnUiThread(new Runnable() { // from class: b.a.a.a.t.p.f
            @Override // java.lang.Runnable
            public final void run() {
                C2354n.m2379B1("下载失败，请重试");
            }
        });
    }

    @Override // p005b.p327w.p330b.p337d.C2859c.c
    public void onDownloadSuccess() {
        this.$dialog.dismiss();
        SplashActivity splashActivity = this.this$0;
        StringBuilder sb = new StringBuilder();
        MyApp myApp = MyApp.f9891f;
        File externalFilesDir = MyApp.m4183d().getExternalFilesDir("apk");
        Intrinsics.checkNotNull(externalFilesDir);
        String absolutePath = externalFilesDir.getAbsolutePath();
        Intrinsics.checkNotNullExpressionValue(absolutePath, "MyApp.instance.getExternalFilesDir(\"apk\")!!.absolutePath");
        sb.append(absolutePath);
        sb.append((Object) File.separator);
        sb.append("new.apk");
        splashActivity.requestInstall(sb.toString());
    }

    @Override // p005b.p327w.p330b.p337d.C2859c.c
    public void onDownloadSuccessData(@NotNull String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.$dialog.dismiss();
    }

    @Override // p005b.p327w.p330b.p337d.C2859c.c
    public void onDownloading(@Nullable ProgressInfo progress) {
        if (progress == null) {
            return;
        }
        this.$dialog.setProgress(progress.m5618b());
    }
}
