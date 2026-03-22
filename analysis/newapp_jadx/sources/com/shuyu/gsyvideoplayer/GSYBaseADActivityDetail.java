package com.shuyu.gsyvideoplayer;

import android.content.res.Configuration;
import com.shuyu.gsyvideoplayer.video.GSYADVideoPlayer;
import com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer;
import com.shuyu.gsyvideoplayer.video.base.GSYVideoPlayer;
import p005b.p362y.p363a.C2918a;

/* loaded from: classes2.dex */
public abstract class GSYBaseADActivityDetail<T extends GSYBaseVideoPlayer, R extends GSYADVideoPlayer> extends GSYBaseActivityDetail<T> {
    /* renamed from: b */
    public abstract R m4633b();

    @Override // com.shuyu.gsyvideoplayer.GSYBaseActivityDetail, androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        if (C2918a.m3389b(this)) {
            return;
        }
        super.onBackPressed();
    }

    @Override // com.shuyu.gsyvideoplayer.GSYBaseActivityDetail, androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
        boolean z = this.f10759c;
        if (!this.f10760e && m4633b().getVisibility() == 0) {
            if ((m4633b().getCurrentPlayer().getCurrentState() < 0 || m4633b().getCurrentPlayer().getCurrentState() == 0 || m4633b().getCurrentPlayer().getCurrentState() == 6) ? false : true) {
                this.f10759c = false;
                m4633b().getCurrentPlayer().onConfigurationChanged(this, configuration, null, true, true);
            }
        }
        super.onConfigurationChanged(configuration);
        this.f10759c = z;
    }

    @Override // com.shuyu.gsyvideoplayer.GSYBaseActivityDetail, androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        C2918a.m3391d();
    }

    @Override // com.shuyu.gsyvideoplayer.GSYBaseActivityDetail, p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onEnterFullscreen(String str, Object... objArr) {
        ((GSYVideoPlayer) objArr[1]).getBackButton().setVisibility(8);
    }

    @Override // com.shuyu.gsyvideoplayer.GSYBaseActivityDetail, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onPause() {
        super.onPause();
        if (C2918a.m3390c().listener() != null) {
            C2918a.m3390c().listener().onVideoPause();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.GSYBaseActivityDetail, p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onPrepared(String str, Object... objArr) {
        throw new NullPointerException("initVideo() or initVideoBuilderMode() first");
    }

    @Override // com.shuyu.gsyvideoplayer.GSYBaseActivityDetail, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        if (C2918a.m3390c().listener() != null) {
            C2918a.m3390c().listener().onVideoResume();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.GSYBaseActivityDetail, p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onStartPrepared(String str, Object... objArr) {
    }
}
