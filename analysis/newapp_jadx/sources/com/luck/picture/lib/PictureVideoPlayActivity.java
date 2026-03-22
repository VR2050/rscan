package com.luck.picture.lib;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.media.MediaPlayer;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcelable;
import android.text.TextUtils;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.MediaController;
import android.widget.TextView;
import android.widget.VideoView;
import androidx.core.view.ViewCompat;
import com.luck.picture.lib.PictureVideoPlayActivity;
import com.luck.picture.lib.config.PictureConfig;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.style.PictureParameterStyle;
import com.luck.picture.lib.style.PictureWindowAnimationStyle;
import com.luck.picture.lib.tools.SdkVersionUtils;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public class PictureVideoPlayActivity extends PictureBaseActivity implements MediaPlayer.OnErrorListener, MediaPlayer.OnPreparedListener, MediaPlayer.OnCompletionListener, View.OnClickListener {
    private ImageButton ibLeftBack;
    private ImageView iv_play;
    private MediaController mMediaController;
    private int mPositionWhenPaused = -1;
    private VideoView mVideoView;
    private TextView tvConfirm;
    private String videoPath;

    /* renamed from: a */
    public /* synthetic */ boolean m4533a(MediaPlayer mediaPlayer, int i2, int i3) {
        if (i2 != 3) {
            return false;
        }
        this.mVideoView.setBackgroundColor(0);
        return true;
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.appcompat.app.AppCompatActivity, android.app.Activity, android.view.ContextThemeWrapper, android.content.ContextWrapper
    public void attachBaseContext(Context context) {
        super.attachBaseContext(new ContextWrapper(context) { // from class: com.luck.picture.lib.PictureVideoPlayActivity.1
            @Override // android.content.ContextWrapper, android.content.Context
            public Object getSystemService(String str) {
                return "audio".equals(str) ? getApplicationContext().getSystemService(str) : super.getSystemService(str);
            }
        });
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public int getResourceId() {
        return C3979R.layout.picture_activity_video_play;
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void initPictureSelectorStyle() {
        int i2;
        PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
        if (pictureParameterStyle == null || (i2 = pictureParameterStyle.pictureLeftBackIcon) == 0) {
            return;
        }
        this.ibLeftBack.setImageResource(i2);
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void initWidgets() {
        super.initWidgets();
        this.videoPath = getIntent().getStringExtra(PictureConfig.EXTRA_VIDEO_PATH);
        boolean booleanExtra = getIntent().getBooleanExtra(PictureConfig.EXTRA_PREVIEW_VIDEO, false);
        if (TextUtils.isEmpty(this.videoPath)) {
            LocalMedia localMedia = (LocalMedia) getIntent().getParcelableExtra(PictureConfig.EXTRA_MEDIA_KEY);
            if (localMedia == null || TextUtils.isEmpty(localMedia.getPath())) {
                finish();
                return;
            }
            this.videoPath = localMedia.getPath();
        }
        if (TextUtils.isEmpty(this.videoPath)) {
            exit();
            return;
        }
        this.ibLeftBack = (ImageButton) findViewById(C3979R.id.pictureLeftBack);
        this.mVideoView = (VideoView) findViewById(C3979R.id.video_view);
        this.tvConfirm = (TextView) findViewById(C3979R.id.tv_confirm);
        this.mVideoView.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
        this.iv_play = (ImageView) findViewById(C3979R.id.iv_play);
        this.mMediaController = new MediaController(this);
        this.mVideoView.setOnCompletionListener(this);
        this.mVideoView.setOnPreparedListener(this);
        this.mVideoView.setMediaController(this.mMediaController);
        this.ibLeftBack.setOnClickListener(this);
        this.iv_play.setOnClickListener(this);
        this.tvConfirm.setOnClickListener(this);
        TextView textView = this.tvConfirm;
        PictureSelectionConfig pictureSelectionConfig = this.config;
        textView.setVisibility((pictureSelectionConfig.selectionMode == 1 && pictureSelectionConfig.enPreviewVideo && !booleanExtra) ? 0 : 8);
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, android.app.Activity
    public boolean isImmersive() {
        return false;
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public boolean isRequestedOrientation() {
        return false;
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        PictureWindowAnimationStyle pictureWindowAnimationStyle = PictureSelectionConfig.windowAnimationStyle;
        if (pictureWindowAnimationStyle == null || pictureWindowAnimationStyle.activityPreviewExitAnimation == 0) {
            exit();
        } else {
            finish();
            overridePendingTransition(0, PictureSelectionConfig.windowAnimationStyle.activityPreviewExitAnimation);
        }
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        int id = view.getId();
        if (id == C3979R.id.pictureLeftBack) {
            onBackPressed();
            return;
        }
        if (id == C3979R.id.iv_play) {
            this.mVideoView.start();
            this.iv_play.setVisibility(4);
        } else if (id == C3979R.id.tv_confirm) {
            ArrayList<? extends Parcelable> arrayList = new ArrayList<>();
            arrayList.add(getIntent().getParcelableExtra(PictureConfig.EXTRA_MEDIA_KEY));
            setResult(-1, new Intent().putParcelableArrayListExtra(PictureConfig.EXTRA_SELECT_LIST, arrayList));
            onBackPressed();
        }
    }

    @Override // android.media.MediaPlayer.OnCompletionListener
    public void onCompletion(MediaPlayer mediaPlayer) {
        ImageView imageView = this.iv_play;
        if (imageView != null) {
            imageView.setVisibility(0);
        }
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        getWindow().addFlags(67108864);
        super.onCreate(bundle);
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        this.mMediaController = null;
        this.mVideoView = null;
        this.iv_play = null;
        super.onDestroy();
    }

    @Override // android.media.MediaPlayer.OnErrorListener
    public boolean onError(MediaPlayer mediaPlayer, int i2, int i3) {
        return false;
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onPause() {
        this.mPositionWhenPaused = this.mVideoView.getCurrentPosition();
        this.mVideoView.stopPlayback();
        super.onPause();
    }

    @Override // android.media.MediaPlayer.OnPreparedListener
    public void onPrepared(MediaPlayer mediaPlayer) {
        mediaPlayer.setOnInfoListener(new MediaPlayer.OnInfoListener() { // from class: b.t.a.a.g0
            @Override // android.media.MediaPlayer.OnInfoListener
            public final boolean onInfo(MediaPlayer mediaPlayer2, int i2, int i3) {
                return PictureVideoPlayActivity.this.m4533a(mediaPlayer2, i2, i3);
            }
        });
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        int i2 = this.mPositionWhenPaused;
        if (i2 >= 0) {
            this.mVideoView.seekTo(i2);
            this.mPositionWhenPaused = -1;
        }
        super.onResume();
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onStart() {
        if (SdkVersionUtils.checkedAndroid_Q() && PictureMimeType.isContent(this.videoPath)) {
            this.mVideoView.setVideoURI(Uri.parse(this.videoPath));
        } else {
            this.mVideoView.setVideoPath(this.videoPath);
        }
        this.mVideoView.start();
        super.onStart();
    }
}
