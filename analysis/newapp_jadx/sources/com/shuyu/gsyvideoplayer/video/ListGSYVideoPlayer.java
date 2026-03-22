package com.shuyu.gsyvideoplayer.video;

import android.content.Context;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer;
import com.shuyu.gsyvideoplayer.video.base.GSYVideoPlayer;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import moe.codeest.enviews.ENDownloadView;
import p005b.p362y.p363a.p367g.C2933b;

/* loaded from: classes2.dex */
public class ListGSYVideoPlayer extends StandardGSYVideoPlayer {
    public int mPlayPosition;
    public List<C2933b> mUriList;

    public ListGSYVideoPlayer(Context context, Boolean bool) {
        super(context, bool);
        this.mUriList = new ArrayList();
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToNormal() {
        super.changeUiToNormal();
        if (!this.mHadPlay || this.mPlayPosition >= this.mUriList.size()) {
            return;
        }
        setViewShowState(this.mThumbImageViewLayout, 8);
        setViewShowState(this.mTopContainer, 4);
        setViewShowState(this.mBottomContainer, 4);
        setViewShowState(this.mStartButton, 8);
        setViewShowState(this.mLoadingProgressBar, 0);
        setViewShowState(this.mBottomProgressBar, 4);
        setViewShowState(this.mLockScreen, 8);
        View view = this.mLoadingProgressBar;
        if (view instanceof ENDownloadView) {
            ((ENDownloadView) view).m5645c();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public void cloneParams(GSYBaseVideoPlayer gSYBaseVideoPlayer, GSYBaseVideoPlayer gSYBaseVideoPlayer2) {
        super.cloneParams(gSYBaseVideoPlayer, gSYBaseVideoPlayer2);
        ListGSYVideoPlayer listGSYVideoPlayer = (ListGSYVideoPlayer) gSYBaseVideoPlayer;
        ListGSYVideoPlayer listGSYVideoPlayer2 = (ListGSYVideoPlayer) gSYBaseVideoPlayer2;
        listGSYVideoPlayer2.mPlayPosition = listGSYVideoPlayer.mPlayPosition;
        listGSYVideoPlayer2.mUriList = listGSYVideoPlayer.mUriList;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onAutoCompletion() {
        if (playNext()) {
            return;
        }
        super.onAutoCompletion();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onCompletion() {
        releaseNetWorkState();
        if (this.mPlayPosition < this.mUriList.size()) {
            return;
        }
        super.onCompletion();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView, p005b.p362y.p363a.p366f.InterfaceC2925a
    public void onPrepared() {
        super.onPrepared();
    }

    public boolean playNext() {
        if (this.mPlayPosition >= this.mUriList.size() - 1) {
            return false;
        }
        int i2 = this.mPlayPosition + 1;
        this.mPlayPosition = i2;
        C2933b c2933b = this.mUriList.get(i2);
        this.mSaveChangeViewTIme = 0L;
        setUp(this.mUriList, this.mCache, this.mPlayPosition, null, this.mMapHeadData, false);
        if (!TextUtils.isEmpty(c2933b.getTitle())) {
            this.mTitleTextView.setText(c2933b.getTitle());
        }
        startPlayLogic();
        return true;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void prepareVideo() {
        super.prepareVideo();
        if (!this.mHadPlay || this.mPlayPosition >= this.mUriList.size()) {
            return;
        }
        setViewShowState(this.mLoadingProgressBar, 0);
        View view = this.mLoadingProgressBar;
        if (view instanceof ENDownloadView) {
            ((ENDownloadView) view).m5645c();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public void resolveNormalVideoShow(View view, ViewGroup viewGroup, GSYVideoPlayer gSYVideoPlayer) {
        if (gSYVideoPlayer != null) {
            C2933b c2933b = this.mUriList.get(this.mPlayPosition);
            if (!TextUtils.isEmpty(c2933b.getTitle())) {
                this.mTitleTextView.setText(c2933b.getTitle());
            }
        }
        super.resolveNormalVideoShow(view, viewGroup, gSYVideoPlayer);
    }

    public boolean setUp(List<C2933b> list, boolean z, int i2) {
        return setUp(list, z, i2, (File) null, new HashMap());
    }

    @Override // com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public GSYBaseVideoPlayer startWindowFullscreen(Context context, boolean z, boolean z2) {
        GSYBaseVideoPlayer startWindowFullscreen = super.startWindowFullscreen(context, z, z2);
        if (startWindowFullscreen != null) {
            ListGSYVideoPlayer listGSYVideoPlayer = (ListGSYVideoPlayer) startWindowFullscreen;
            C2933b c2933b = this.mUriList.get(this.mPlayPosition);
            if (!TextUtils.isEmpty(c2933b.getTitle())) {
                listGSYVideoPlayer.mTitleTextView.setText(c2933b.getTitle());
            }
        }
        return startWindowFullscreen;
    }

    public boolean setUp(List<C2933b> list, boolean z, int i2, File file) {
        return setUp(list, z, i2, file, new HashMap());
    }

    public ListGSYVideoPlayer(Context context) {
        super(context);
        this.mUriList = new ArrayList();
    }

    public boolean setUp(List<C2933b> list, boolean z, int i2, File file, Map<String, String> map) {
        return setUp(list, z, i2, file, map, true);
    }

    public boolean setUp(List<C2933b> list, boolean z, int i2, File file, Map<String, String> map, boolean z2) {
        this.mUriList = list;
        this.mPlayPosition = i2;
        this.mMapHeadData = map;
        C2933b c2933b = list.get(i2);
        boolean up = setUp(c2933b.getUrl(), z, file, c2933b.getTitle(), z2);
        if (!TextUtils.isEmpty(c2933b.getTitle())) {
            this.mTitleTextView.setText(c2933b.getTitle());
        }
        return up;
    }

    public ListGSYVideoPlayer(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.mUriList = new ArrayList();
    }
}
