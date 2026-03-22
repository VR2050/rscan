package p005b.p362y.p363a.p364d;

import android.graphics.drawable.Drawable;
import android.view.View;
import com.shuyu.gsyvideoplayer.render.view.GSYVideoGLView;
import com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer;
import com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer;
import java.io.File;
import java.util.Map;
import p005b.p362y.p363a.p366f.InterfaceC2927c;
import p005b.p362y.p363a.p366f.InterfaceC2930f;
import p005b.p362y.p363a.p366f.InterfaceC2931g;
import p005b.p362y.p363a.p369i.p370b.C2940a;

/* renamed from: b.y.a.d.a */
/* loaded from: classes2.dex */
public class C2921a {
    public Drawable mBottomProgressDrawable;
    public Drawable mBottomShowProgressDrawable;
    public Drawable mBottomShowProgressThumbDrawable;
    public File mCachePath;
    public boolean mCacheWithPlay;
    public Drawable mDialogProgressBarDrawable;
    public InterfaceC2927c mGSYVideoProgressListener;
    public InterfaceC2930f mLockClickListener;
    public Map<String, String> mMapHeadData;
    public boolean mNeedLockFull;
    public String mOverrideExtension;
    public boolean mSounchTouch;
    public View mThumbImageView;
    public boolean mThumbPlay;
    public String mUrl;
    public InterfaceC2931g mVideoAllCallBack;
    public Drawable mVolumeProgressDrawable;
    public int mShrinkImageRes = -1;
    public int mEnlargeImageRes = -1;
    public int mPlayPosition = -22;
    public int mDialogProgressHighLightColor = -11;
    public int mDialogProgressNormalColor = -11;
    public int mDismissControlTime = 2500;
    public long mSeekOnStart = -1;
    public float mSeekRatio = 1.0f;
    public float mSpeed = 1.0f;
    public boolean mHideKey = true;
    public boolean mShowFullAnimation = true;
    public boolean mAutoFullWithSize = false;
    public boolean mNeedShowWifiTip = true;
    public boolean mRotateViewAuto = true;
    public boolean mLockLand = false;
    public boolean mLooping = false;
    public boolean mIsTouchWiget = true;
    public boolean mIsTouchWigetFull = true;
    public boolean mShowPauseCover = true;
    public boolean mRotateWithSystem = true;
    public boolean mSetUpLazy = false;
    public boolean mStartAfterPrepared = true;
    public boolean mReleaseWhenLossAudio = true;
    public boolean mActionBar = false;
    public boolean mStatusBar = false;
    public boolean isShowDragProgressTextOnSeekBar = false;
    public String mPlayTag = "";
    public String mVideoTitle = null;
    private boolean mIsOnlyRotateLand = false;
    public GSYVideoGLView.InterfaceC4091c mEffectFilter = new C2940a();

    public void build(StandardGSYVideoPlayer standardGSYVideoPlayer) {
        int i2;
        Drawable drawable;
        Drawable drawable2 = this.mBottomShowProgressDrawable;
        if (drawable2 != null && (drawable = this.mBottomShowProgressThumbDrawable) != null) {
            standardGSYVideoPlayer.setBottomShowProgressBarDrawable(drawable2, drawable);
        }
        Drawable drawable3 = this.mBottomProgressDrawable;
        if (drawable3 != null) {
            standardGSYVideoPlayer.setBottomProgressBarDrawable(drawable3);
        }
        Drawable drawable4 = this.mVolumeProgressDrawable;
        if (drawable4 != null) {
            standardGSYVideoPlayer.setDialogVolumeProgressBar(drawable4);
        }
        Drawable drawable5 = this.mDialogProgressBarDrawable;
        if (drawable5 != null) {
            standardGSYVideoPlayer.setDialogProgressBar(drawable5);
        }
        int i3 = this.mDialogProgressHighLightColor;
        if (i3 > 0 && (i2 = this.mDialogProgressNormalColor) > 0) {
            standardGSYVideoPlayer.setDialogProgressColor(i3, i2);
        }
        build((GSYBaseVideoPlayer) standardGSYVideoPlayer);
    }

    public C2921a setAutoFullWithSize(boolean z) {
        this.mAutoFullWithSize = z;
        return this;
    }

    public C2921a setBottomProgressBarDrawable(Drawable drawable) {
        this.mBottomProgressDrawable = drawable;
        return this;
    }

    public C2921a setBottomShowProgressBarDrawable(Drawable drawable, Drawable drawable2) {
        this.mBottomShowProgressDrawable = drawable;
        this.mBottomShowProgressThumbDrawable = drawable2;
        return this;
    }

    public C2921a setCachePath(File file) {
        this.mCachePath = file;
        return this;
    }

    public C2921a setCacheWithPlay(boolean z) {
        this.mCacheWithPlay = z;
        return this;
    }

    public C2921a setDialogProgressBar(Drawable drawable) {
        this.mDialogProgressBarDrawable = drawable;
        return this;
    }

    public C2921a setDialogProgressColor(int i2, int i3) {
        this.mDialogProgressHighLightColor = i2;
        this.mDialogProgressNormalColor = i3;
        return this;
    }

    public C2921a setDialogVolumeProgressBar(Drawable drawable) {
        this.mVolumeProgressDrawable = drawable;
        return this;
    }

    public C2921a setDismissControlTime(int i2) {
        this.mDismissControlTime = i2;
        return this;
    }

    public C2921a setEffectFilter(GSYVideoGLView.InterfaceC4091c interfaceC4091c) {
        this.mEffectFilter = interfaceC4091c;
        return this;
    }

    public C2921a setEnlargeImageRes(int i2) {
        this.mEnlargeImageRes = i2;
        return this;
    }

    public C2921a setFullHideActionBar(boolean z) {
        this.mActionBar = z;
        return this;
    }

    public C2921a setFullHideStatusBar(boolean z) {
        this.mStatusBar = z;
        return this;
    }

    public C2921a setGSYVideoProgressListener(InterfaceC2927c interfaceC2927c) {
        this.mGSYVideoProgressListener = interfaceC2927c;
        return this;
    }

    public C2921a setHideKey(boolean z) {
        this.mHideKey = z;
        return this;
    }

    public C2921a setIsTouchWiget(boolean z) {
        this.mIsTouchWiget = z;
        return this;
    }

    public C2921a setIsTouchWigetFull(boolean z) {
        this.mIsTouchWigetFull = z;
        return this;
    }

    public C2921a setLockClickListener(InterfaceC2930f interfaceC2930f) {
        this.mLockClickListener = interfaceC2930f;
        return this;
    }

    public C2921a setLockLand(boolean z) {
        this.mLockLand = z;
        return this;
    }

    public C2921a setLooping(boolean z) {
        this.mLooping = z;
        return this;
    }

    public C2921a setMapHeadData(Map<String, String> map) {
        this.mMapHeadData = map;
        return this;
    }

    public C2921a setNeedLockFull(boolean z) {
        this.mNeedLockFull = z;
        return this;
    }

    public C2921a setNeedShowWifiTip(boolean z) {
        this.mNeedShowWifiTip = z;
        return this;
    }

    public C2921a setOnlyRotateLand(boolean z) {
        this.mIsOnlyRotateLand = z;
        return this;
    }

    public C2921a setOverrideExtension(String str) {
        this.mOverrideExtension = str;
        return this;
    }

    public C2921a setPlayPosition(int i2) {
        this.mPlayPosition = i2;
        return this;
    }

    public C2921a setPlayTag(String str) {
        this.mPlayTag = str;
        return this;
    }

    public C2921a setReleaseWhenLossAudio(boolean z) {
        this.mReleaseWhenLossAudio = z;
        return this;
    }

    public C2921a setRotateViewAuto(boolean z) {
        this.mRotateViewAuto = z;
        return this;
    }

    public C2921a setRotateWithSystem(boolean z) {
        this.mRotateWithSystem = z;
        return this;
    }

    public C2921a setSeekOnStart(long j2) {
        this.mSeekOnStart = j2;
        return this;
    }

    public C2921a setSeekRatio(float f2) {
        if (f2 < 0.0f) {
            return this;
        }
        this.mSeekRatio = f2;
        return this;
    }

    @Deprecated
    public C2921a setSetUpLazy(boolean z) {
        this.mSetUpLazy = z;
        return this;
    }

    public C2921a setShowDragProgressTextOnSeekBar(boolean z) {
        this.isShowDragProgressTextOnSeekBar = z;
        return this;
    }

    public C2921a setShowFullAnimation(boolean z) {
        this.mShowFullAnimation = z;
        return this;
    }

    public C2921a setShowPauseCover(boolean z) {
        this.mShowPauseCover = z;
        return this;
    }

    public C2921a setShrinkImageRes(int i2) {
        this.mShrinkImageRes = i2;
        return this;
    }

    public C2921a setSoundTouch(boolean z) {
        this.mSounchTouch = z;
        return this;
    }

    public C2921a setSpeed(float f2) {
        this.mSpeed = f2;
        return this;
    }

    public C2921a setStartAfterPrepared(boolean z) {
        this.mStartAfterPrepared = z;
        return this;
    }

    public C2921a setThumbImageView(View view) {
        this.mThumbImageView = view;
        return this;
    }

    public C2921a setThumbPlay(boolean z) {
        this.mThumbPlay = z;
        return this;
    }

    public C2921a setUrl(String str) {
        this.mUrl = str;
        return this;
    }

    public C2921a setVideoAllCallBack(InterfaceC2931g interfaceC2931g) {
        this.mVideoAllCallBack = interfaceC2931g;
        return this;
    }

    public C2921a setVideoTitle(String str) {
        this.mVideoTitle = str;
        return this;
    }

    public void build(GSYBaseVideoPlayer gSYBaseVideoPlayer) {
        gSYBaseVideoPlayer.setPlayTag(this.mPlayTag);
        gSYBaseVideoPlayer.setPlayPosition(this.mPlayPosition);
        gSYBaseVideoPlayer.setThumbPlay(this.mThumbPlay);
        View view = this.mThumbImageView;
        if (view != null) {
            gSYBaseVideoPlayer.setThumbImageView(view);
        }
        gSYBaseVideoPlayer.setNeedLockFull(this.mNeedLockFull);
        InterfaceC2930f interfaceC2930f = this.mLockClickListener;
        if (interfaceC2930f != null) {
            gSYBaseVideoPlayer.setLockClickListener(interfaceC2930f);
        }
        gSYBaseVideoPlayer.setDismissControlTime(this.mDismissControlTime);
        long j2 = this.mSeekOnStart;
        if (j2 > 0) {
            gSYBaseVideoPlayer.setSeekOnStart(j2);
        }
        gSYBaseVideoPlayer.setShowFullAnimation(this.mShowFullAnimation);
        gSYBaseVideoPlayer.setLooping(this.mLooping);
        InterfaceC2931g interfaceC2931g = this.mVideoAllCallBack;
        if (interfaceC2931g != null) {
            gSYBaseVideoPlayer.setVideoAllCallBack(interfaceC2931g);
        }
        InterfaceC2927c interfaceC2927c = this.mGSYVideoProgressListener;
        if (interfaceC2927c != null) {
            gSYBaseVideoPlayer.setGSYVideoProgressListener(interfaceC2927c);
        }
        gSYBaseVideoPlayer.setOverrideExtension(this.mOverrideExtension);
        gSYBaseVideoPlayer.setAutoFullWithSize(this.mAutoFullWithSize);
        gSYBaseVideoPlayer.setRotateViewAuto(this.mRotateViewAuto);
        gSYBaseVideoPlayer.setOnlyRotateLand(this.mIsOnlyRotateLand);
        gSYBaseVideoPlayer.setLockLand(this.mLockLand);
        gSYBaseVideoPlayer.setSpeed(this.mSpeed, this.mSounchTouch);
        gSYBaseVideoPlayer.setHideKey(this.mHideKey);
        gSYBaseVideoPlayer.setIsTouchWiget(this.mIsTouchWiget);
        gSYBaseVideoPlayer.setIsTouchWigetFull(this.mIsTouchWigetFull);
        gSYBaseVideoPlayer.setNeedShowWifiTip(this.mNeedShowWifiTip);
        gSYBaseVideoPlayer.setEffectFilter(this.mEffectFilter);
        gSYBaseVideoPlayer.setStartAfterPrepared(this.mStartAfterPrepared);
        gSYBaseVideoPlayer.setReleaseWhenLossAudio(this.mReleaseWhenLossAudio);
        gSYBaseVideoPlayer.setFullHideActionBar(this.mActionBar);
        gSYBaseVideoPlayer.setShowDragProgressTextOnSeekBar(this.isShowDragProgressTextOnSeekBar);
        gSYBaseVideoPlayer.setFullHideStatusBar(this.mStatusBar);
        int i2 = this.mEnlargeImageRes;
        if (i2 > 0) {
            gSYBaseVideoPlayer.setEnlargeImageRes(i2);
        }
        int i3 = this.mShrinkImageRes;
        if (i3 > 0) {
            gSYBaseVideoPlayer.setShrinkImageRes(i3);
        }
        gSYBaseVideoPlayer.setShowPauseCover(this.mShowPauseCover);
        gSYBaseVideoPlayer.setSeekRatio(this.mSeekRatio);
        gSYBaseVideoPlayer.setRotateWithSystem(this.mRotateWithSystem);
        if (this.mSetUpLazy) {
            gSYBaseVideoPlayer.setUpLazy(this.mUrl, this.mCacheWithPlay, this.mCachePath, this.mMapHeadData, this.mVideoTitle);
        } else {
            gSYBaseVideoPlayer.setUp(this.mUrl, this.mCacheWithPlay, this.mCachePath, this.mMapHeadData, this.mVideoTitle);
        }
    }
}
