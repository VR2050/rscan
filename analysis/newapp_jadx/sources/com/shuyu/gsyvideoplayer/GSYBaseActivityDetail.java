package com.shuyu.gsyvideoplayer;

import android.content.res.Configuration;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer;
import p005b.p362y.p363a.C2920c;
import p005b.p362y.p363a.p366f.InterfaceC2931g;

/* loaded from: classes2.dex */
public abstract class GSYBaseActivityDetail<T extends GSYBaseVideoPlayer> extends AppCompatActivity implements InterfaceC2931g {

    /* renamed from: c */
    public boolean f10759c;

    /* renamed from: e */
    public boolean f10760e;

    /* renamed from: a */
    public abstract T m4634a();

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onAutoComplete(String str, Object... objArr) {
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        if (C2920c.m3393b(this)) {
            return;
        }
        super.onBackPressed();
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onClickBlank(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onClickBlankFullscreen(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onClickResume(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onClickResumeFullscreen(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onClickSeekbar(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onClickSeekbarFullscreen(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onClickStartError(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onClickStartIcon(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onClickStartThumb(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onClickStop(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onClickStopFullscreen(String str, Object... objArr) {
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        if (!this.f10759c || this.f10760e) {
            return;
        }
        m4634a().onConfigurationChanged(this, configuration, null, true, true);
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        if (this.f10759c) {
            m4634a().getCurrentPlayer().release();
        }
    }

    public void onEnterFullscreen(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onEnterSmallWidget(String str, Object... objArr) {
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onPause() {
        super.onPause();
        m4634a().getCurrentPlayer().onVideoPause();
        this.f10760e = true;
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onPlayError(String str, Object... objArr) {
    }

    public void onPrepared(String str, Object... objArr) {
        throw new NullPointerException("initVideo() or initVideoBuilderMode() first");
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onQuitFullscreen(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onQuitSmallWidget(String str, Object... objArr) {
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        m4634a().getCurrentPlayer().onVideoResume();
        this.f10760e = false;
    }

    public void onStartPrepared(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onTouchScreenSeekLight(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onTouchScreenSeekPosition(String str, Object... objArr) {
    }

    @Override // p005b.p362y.p363a.p366f.InterfaceC2931g
    public void onTouchScreenSeekVolume(String str, Object... objArr) {
    }
}
