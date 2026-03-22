package com.jbzd.media.movecartoons.p396ui.accountvoucher;

import android.content.Intent;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.view.View;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.p396ui.accountvoucher.ScanActivity;
import com.king.zxing.CaptureActivity;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p310s.p311a.C2736f;
import p005b.p310s.p311a.C2737g;
import p005b.p310s.p311a.C2740j;
import p005b.p310s.p311a.HandlerC2738h;
import p005b.p310s.p311a.InterfaceC2744n;
import p005b.p310s.p311a.SurfaceHolderCallbackC2739i;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\n\u0010\u000bJ\u0019\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u0014¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\t¨\u0006\f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/accountvoucher/ScanActivity;", "Lcom/king/zxing/CaptureActivity;", "Landroid/os/Bundle;", "savedInstanceState", "", "onCreate", "(Landroid/os/Bundle;)V", "", "getLayoutId", "()I", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ScanActivity extends CaptureActivity {
    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: onCreate$lambda-0, reason: not valid java name */
    public static final boolean m5744onCreate$lambda0(ScanActivity this$0, String str) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intent intent = new Intent();
        intent.putExtra(CaptureActivity.KEY_RESULT, str);
        this$0.setResult(-1, intent);
        this$0.finish();
        Intrinsics.stringPlus("result :", str);
        return true;
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.king.zxing.CaptureActivity
    public int getLayoutId() {
        return R.layout.act_scan;
    }

    @Override // com.king.zxing.CaptureActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ImmersionBar.with(this).navigationBarColor("#000000").statusBarDarkFont(true).init();
        C2354n.m2374A((RelativeLayout) findViewById(R$id.btn_titleBack), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.accountvoucher.ScanActivity$onCreate$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                invoke2(relativeLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(RelativeLayout relativeLayout) {
                ScanActivity.this.finish();
            }
        }, 1);
        ((TextView) findViewById(R$id.tv_title)).setText("扫描二维码");
        SurfaceHolderCallbackC2739i captureHelper = getCaptureHelper();
        captureHelper.f7481w = true;
        C2737g c2737g = captureHelper.f7468j;
        if (c2737g != null) {
            c2737g.f7448g = true;
        }
        captureHelper.f7482x = true;
        if (c2737g != null) {
            c2737g.f7449h = true;
        }
        captureHelper.f7473o = C2740j.f7488d;
        PreferenceManager.getDefaultSharedPreferences(captureHelper.f7463e).edit().putString("preferences_front_light_mode", "AUTO").commit();
        View view = captureHelper.f7472n;
        captureHelper.f7484z = 45.0f;
        C2736f c2736f = captureHelper.f7469k;
        if (c2736f != null) {
            c2736f.f7440a = 45.0f;
        }
        captureHelper.f7460A = 100.0f;
        if (c2736f != null) {
            c2736f.f7440a = 45.0f;
        }
        captureHelper.f7479u = false;
        captureHelper.f7478t = true;
        HandlerC2738h handlerC2738h = captureHelper.f7464f;
        if (handlerC2738h != null) {
            handlerC2738h.f7458l = true;
        }
        captureHelper.f7461B = new InterfaceC2744n() { // from class: b.a.a.a.t.a.c
            @Override // p005b.p310s.p311a.InterfaceC2744n
            public final boolean onResultCallback(String str) {
                boolean m5744onCreate$lambda0;
                m5744onCreate$lambda0 = ScanActivity.m5744onCreate$lambda0(ScanActivity.this, str);
                return m5744onCreate$lambda0;
            }
        };
    }
}
