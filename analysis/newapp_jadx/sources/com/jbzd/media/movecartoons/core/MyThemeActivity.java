package com.jbzd.media.movecartoons.core;

import androidx.exifinterface.media.ExifInterface;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseThemeActivity;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p023s.C0959d0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\b&\u0018\u0000*\u0004\b\u0000\u0010\u00012\u00020\u0002B\u0007¢\u0006\u0004\b\u0012\u0010\tJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ\r\u0010\u000b\u001a\u00020\n¢\u0006\u0004\b\u000b\u0010\fR\u0019\u0010\u000e\u001a\u00020\r8\u0006@\u0006¢\u0006\f\n\u0004\b\u000e\u0010\u000f\u001a\u0004\b\u0010\u0010\u0011¨\u0006\u0013"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", ExifInterface.GPS_DIRECTION_TRUE, "Lcom/qunidayede/supportlibrary/core/view/BaseThemeActivity;", "", "isDay", "", "setThemeRes", "(Z)V", "notifyThemeChanged", "()V", "", "getEmptyTips", "()Ljava/lang/String;", "Lb/a/a/a/s/d0;", "audioService", "Lb/a/a/a/s/d0;", "getAudioService", "()Lb/a/a/a/s/d0;", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class MyThemeActivity<T> extends BaseThemeActivity {

    @NotNull
    private final C0959d0 audioService;

    public MyThemeActivity() {
        if (C0959d0.f570a == null) {
            synchronized (C0959d0.class) {
                if (C0959d0.f570a == null) {
                    C0959d0.f570a = new C0959d0(null);
                }
                Unit unit = Unit.INSTANCE;
            }
        }
        C0959d0 c0959d0 = C0959d0.f570a;
        Intrinsics.checkNotNull(c0959d0);
        this.audioService = c0959d0;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final C0959d0 getAudioService() {
        return this.audioService;
    }

    @NotNull
    public final String getEmptyTips() {
        return "当前页面暂无订单内容！";
    }

    @Override // p005b.p327w.p330b.p331b.InterfaceC2829b
    public void notifyThemeChanged() {
        recreate();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity
    public void setThemeRes(boolean isDay) {
        setTheme(R.style.AppTheme);
    }
}
