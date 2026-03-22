package com.shuyu.gsyvideoplayer.video;

import android.animation.ValueAnimator;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.animation.AnticipateInterpolator;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.SeekBar;
import android.widget.TextView;
import com.google.android.material.badge.BadgeDrawable;
import com.shuyu.gsyvideoplayer.R$drawable;
import com.shuyu.gsyvideoplayer.R$id;
import com.shuyu.gsyvideoplayer.R$layout;
import com.shuyu.gsyvideoplayer.R$string;
import com.shuyu.gsyvideoplayer.R$style;
import com.shuyu.gsyvideoplayer.utils.Debuger;
import com.shuyu.gsyvideoplayer.utils.NetworkUtils;
import com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer;
import com.shuyu.gsyvideoplayer.video.base.GSYVideoPlayer;
import com.yalantis.ucrop.view.CropImageView;
import java.io.File;
import moe.codeest.enviews.ENDownloadView;
import moe.codeest.enviews.ENPlayView;
import p005b.p362y.p363a.p366f.InterfaceC2928d;
import p005b.p362y.p363a.p366f.InterfaceC2929e;
import p005b.p362y.p363a.p369i.p372d.InterfaceC2944a;
import p455j.p456a.p457a.C4367c;

/* loaded from: classes2.dex */
public class StandardGSYVideoPlayer extends GSYVideoPlayer {
    public Drawable mBottomProgressDrawable;
    public Drawable mBottomShowProgressDrawable;
    public Drawable mBottomShowProgressThumbDrawable;
    public Dialog mBrightnessDialog;
    public TextView mBrightnessDialogTv;
    public ImageView mDialogIcon;
    public ProgressBar mDialogProgressBar;
    public Drawable mDialogProgressBarDrawable;
    public int mDialogProgressHighLightColor;
    public int mDialogProgressNormalColor;
    public TextView mDialogSeekTime;
    public TextView mDialogTotalTime;
    public ProgressBar mDialogVolumeProgressBar;
    public Dialog mProgressDialog;
    public Dialog mVolumeDialog;
    public Drawable mVolumeProgressDrawable;

    public StandardGSYVideoPlayer(Context context, Boolean bool) {
        super(context, bool);
        this.mDialogProgressHighLightColor = -11;
        this.mDialogProgressNormalColor = -11;
    }

    private void initFullUI(StandardGSYVideoPlayer standardGSYVideoPlayer) {
        int i2;
        Drawable drawable;
        Drawable drawable2 = this.mBottomProgressDrawable;
        if (drawable2 != null) {
            standardGSYVideoPlayer.setBottomProgressBarDrawable(drawable2);
        }
        Drawable drawable3 = this.mBottomShowProgressDrawable;
        if (drawable3 != null && (drawable = this.mBottomShowProgressThumbDrawable) != null) {
            standardGSYVideoPlayer.setBottomShowProgressBarDrawable(drawable3, drawable);
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
        if (i3 < 0 || (i2 = this.mDialogProgressNormalColor) < 0) {
            return;
        }
        standardGSYVideoPlayer.setDialogProgressColor(i3, i2);
    }

    public void changeUiToClear() {
        Debuger.printfLog("changeUiToClear");
        setViewShowState(this.mTopContainer, 4);
        setViewShowState(this.mBottomContainer, 4);
        setViewShowState(this.mStartButton, 4);
        setViewShowState(this.mLoadingProgressBar, 4);
        setViewShowState(this.mThumbImageViewLayout, 4);
        setViewShowState(this.mBottomProgressBar, 4);
        setViewShowState(this.mLockScreen, 8);
        View view = this.mLoadingProgressBar;
        if (view instanceof ENDownloadView) {
            ((ENDownloadView) view).m5644b();
        }
    }

    public void changeUiToCompleteClear() {
        Debuger.printfLog("changeUiToCompleteClear");
        setViewShowState(this.mTopContainer, 4);
        setViewShowState(this.mBottomContainer, 4);
        setViewShowState(this.mStartButton, 0);
        setViewShowState(this.mLoadingProgressBar, 4);
        setViewShowState(this.mThumbImageViewLayout, 0);
        setViewShowState(this.mBottomProgressBar, 0);
        setViewShowState(this.mLockScreen, (this.mIfCurrentIsFullscreen && this.mNeedLockFull) ? 0 : 8);
        View view = this.mLoadingProgressBar;
        if (view instanceof ENDownloadView) {
            ((ENDownloadView) view).m5644b();
        }
        updateStartImage();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToCompleteShow() {
        Debuger.printfLog("changeUiToCompleteShow");
        setViewShowState(this.mTopContainer, 0);
        setViewShowState(this.mBottomContainer, 0);
        setViewShowState(this.mStartButton, 0);
        setViewShowState(this.mLoadingProgressBar, 4);
        setViewShowState(this.mThumbImageViewLayout, 0);
        setViewShowState(this.mBottomProgressBar, 4);
        setViewShowState(this.mLockScreen, (this.mIfCurrentIsFullscreen && this.mNeedLockFull) ? 0 : 8);
        View view = this.mLoadingProgressBar;
        if (view instanceof ENDownloadView) {
            ((ENDownloadView) view).m5644b();
        }
        updateStartImage();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToError() {
        Debuger.printfLog("changeUiToError");
        setViewShowState(this.mTopContainer, 4);
        setViewShowState(this.mBottomContainer, 4);
        setViewShowState(this.mStartButton, 0);
        setViewShowState(this.mLoadingProgressBar, 4);
        setViewShowState(this.mThumbImageViewLayout, 4);
        setViewShowState(this.mBottomProgressBar, 4);
        setViewShowState(this.mLockScreen, (this.mIfCurrentIsFullscreen && this.mNeedLockFull) ? 0 : 8);
        View view = this.mLoadingProgressBar;
        if (view instanceof ENDownloadView) {
            ((ENDownloadView) view).m5644b();
        }
        updateStartImage();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToNormal() {
        Debuger.printfLog("changeUiToNormal");
        setViewShowState(this.mTopContainer, 0);
        setViewShowState(this.mBottomContainer, 4);
        setViewShowState(this.mStartButton, 0);
        setViewShowState(this.mLoadingProgressBar, 4);
        setViewShowState(this.mThumbImageViewLayout, 0);
        setViewShowState(this.mBottomProgressBar, 4);
        setViewShowState(this.mLockScreen, (this.mIfCurrentIsFullscreen && this.mNeedLockFull) ? 0 : 8);
        updateStartImage();
        View view = this.mLoadingProgressBar;
        if (view instanceof ENDownloadView) {
            ((ENDownloadView) view).m5644b();
        }
    }

    public void changeUiToPauseClear() {
        Debuger.printfLog("changeUiToPauseClear");
        changeUiToClear();
        setViewShowState(this.mBottomProgressBar, 0);
        updatePauseCover();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToPauseShow() {
        Debuger.printfLog("changeUiToPauseShow");
        setViewShowState(this.mTopContainer, 0);
        setViewShowState(this.mBottomContainer, 0);
        setViewShowState(this.mStartButton, 0);
        setViewShowState(this.mLoadingProgressBar, 4);
        setViewShowState(this.mThumbImageViewLayout, 4);
        setViewShowState(this.mBottomProgressBar, 4);
        setViewShowState(this.mLockScreen, (this.mIfCurrentIsFullscreen && this.mNeedLockFull) ? 0 : 8);
        View view = this.mLoadingProgressBar;
        if (view instanceof ENDownloadView) {
            ((ENDownloadView) view).m5644b();
        }
        updateStartImage();
        updatePauseCover();
    }

    public void changeUiToPlayingBufferingClear() {
        Debuger.printfLog("changeUiToPlayingBufferingClear");
        setViewShowState(this.mTopContainer, 4);
        setViewShowState(this.mBottomContainer, 4);
        setViewShowState(this.mStartButton, 4);
        setViewShowState(this.mLoadingProgressBar, 0);
        setViewShowState(this.mThumbImageViewLayout, 4);
        setViewShowState(this.mBottomProgressBar, 0);
        setViewShowState(this.mLockScreen, 8);
        View view = this.mLoadingProgressBar;
        if ((view instanceof ENDownloadView) && ((ENDownloadView) view).getCurrentState() == 0) {
            ((ENDownloadView) this.mLoadingProgressBar).m5645c();
        }
        updateStartImage();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToPlayingBufferingShow() {
        Debuger.printfLog("changeUiToPlayingBufferingShow");
        setViewShowState(this.mTopContainer, 0);
        setViewShowState(this.mBottomContainer, 0);
        setViewShowState(this.mStartButton, 4);
        setViewShowState(this.mLoadingProgressBar, 0);
        setViewShowState(this.mThumbImageViewLayout, 4);
        setViewShowState(this.mBottomProgressBar, 4);
        setViewShowState(this.mLockScreen, 8);
        View view = this.mLoadingProgressBar;
        if ((view instanceof ENDownloadView) && ((ENDownloadView) view).getCurrentState() == 0) {
            ((ENDownloadView) this.mLoadingProgressBar).m5645c();
        }
    }

    public void changeUiToPlayingClear() {
        Debuger.printfLog("changeUiToPlayingClear");
        changeUiToClear();
        setViewShowState(this.mBottomProgressBar, 0);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToPlayingShow() {
        Debuger.printfLog("changeUiToPlayingShow");
        setViewShowState(this.mTopContainer, 0);
        setViewShowState(this.mBottomContainer, 0);
        setViewShowState(this.mStartButton, 0);
        setViewShowState(this.mLoadingProgressBar, 4);
        setViewShowState(this.mThumbImageViewLayout, 4);
        setViewShowState(this.mBottomProgressBar, 4);
        setViewShowState(this.mLockScreen, (this.mIfCurrentIsFullscreen && this.mNeedLockFull) ? 0 : 8);
        View view = this.mLoadingProgressBar;
        if (view instanceof ENDownloadView) {
            ((ENDownloadView) view).m5644b();
        }
        updateStartImage();
    }

    public void changeUiToPrepareingClear() {
        Debuger.printfLog("changeUiToPrepareingClear");
        setViewShowState(this.mTopContainer, 4);
        setViewShowState(this.mBottomContainer, 4);
        setViewShowState(this.mStartButton, 4);
        setViewShowState(this.mLoadingProgressBar, 4);
        setViewShowState(this.mThumbImageViewLayout, 4);
        setViewShowState(this.mBottomProgressBar, 4);
        setViewShowState(this.mLockScreen, 8);
        View view = this.mLoadingProgressBar;
        if (view instanceof ENDownloadView) {
            ((ENDownloadView) view).m5644b();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void changeUiToPreparingShow() {
        Debuger.printfLog("changeUiToPreparingShow");
        setViewShowState(this.mTopContainer, 0);
        setViewShowState(this.mBottomContainer, 0);
        setViewShowState(this.mStartButton, 4);
        setViewShowState(this.mLoadingProgressBar, 0);
        setViewShowState(this.mThumbImageViewLayout, 4);
        setViewShowState(this.mBottomProgressBar, 4);
        setViewShowState(this.mLockScreen, 8);
        View view = this.mLoadingProgressBar;
        if ((view instanceof ENDownloadView) && ((ENDownloadView) view).getCurrentState() == 0) {
            ((ENDownloadView) this.mLoadingProgressBar).m5645c();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public void cloneParams(GSYBaseVideoPlayer gSYBaseVideoPlayer, GSYBaseVideoPlayer gSYBaseVideoPlayer2) {
        TextView textView;
        TextView textView2;
        SeekBar seekBar;
        super.cloneParams(gSYBaseVideoPlayer, gSYBaseVideoPlayer2);
        StandardGSYVideoPlayer standardGSYVideoPlayer = (StandardGSYVideoPlayer) gSYBaseVideoPlayer;
        StandardGSYVideoPlayer standardGSYVideoPlayer2 = (StandardGSYVideoPlayer) gSYBaseVideoPlayer2;
        SeekBar seekBar2 = standardGSYVideoPlayer2.mProgressBar;
        if (seekBar2 != null && (seekBar = standardGSYVideoPlayer.mProgressBar) != null) {
            seekBar2.setProgress(seekBar.getProgress());
            standardGSYVideoPlayer2.mProgressBar.setSecondaryProgress(standardGSYVideoPlayer.mProgressBar.getSecondaryProgress());
        }
        TextView textView3 = standardGSYVideoPlayer2.mTotalTimeTextView;
        if (textView3 != null && (textView2 = standardGSYVideoPlayer.mTotalTimeTextView) != null) {
            textView3.setText(textView2.getText());
        }
        TextView textView4 = standardGSYVideoPlayer2.mCurrentTimeTextView;
        if (textView4 == null || (textView = standardGSYVideoPlayer.mCurrentTimeTextView) == null) {
            return;
        }
        textView4.setText(textView.getText());
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void dismissBrightnessDialog() {
        Dialog dialog = this.mBrightnessDialog;
        if (dialog != null) {
            dialog.dismiss();
            this.mBrightnessDialog = null;
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void dismissProgressDialog() {
        Dialog dialog = this.mProgressDialog;
        if (dialog != null) {
            dialog.dismiss();
            this.mProgressDialog = null;
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void dismissVolumeDialog() {
        Dialog dialog = this.mVolumeDialog;
        if (dialog != null) {
            dialog.dismiss();
            this.mVolumeDialog = null;
        }
    }

    public int getBrightnessLayoutId() {
        return R$layout.video_brightness;
    }

    public int getBrightnessTextId() {
        return R$id.app_video_brightness;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public int getLayoutId() {
        return R$layout.video_layout_standard;
    }

    public int getProgressDialogAllDurationTextId() {
        return R$id.tv_duration;
    }

    public int getProgressDialogCurrentDurationTextId() {
        return R$id.tv_current;
    }

    public int getProgressDialogImageId() {
        return R$id.duration_image_tip;
    }

    public int getProgressDialogLayoutId() {
        return R$layout.video_progress_dialog;
    }

    public int getProgressDialogProgressId() {
        return R$id.duration_progressbar;
    }

    public int getVolumeLayoutId() {
        return R$layout.video_volume_dialog;
    }

    public int getVolumeProgressId() {
        return R$id.volume_progressbar;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void hideAllWidget() {
        setViewShowState(this.mBottomContainer, 4);
        setViewShowState(this.mTopContainer, 4);
        setViewShowState(this.mBottomProgressBar, 0);
        setViewShowState(this.mStartButton, 4);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer, com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void init(Context context) {
        super.init(context);
        Drawable drawable = this.mBottomProgressDrawable;
        if (drawable != null) {
            this.mBottomProgressBar.setProgressDrawable(drawable);
        }
        if (this.mBottomShowProgressDrawable != null) {
            this.mProgressBar.setProgressDrawable(this.mBottomProgressDrawable);
        }
        Drawable drawable2 = this.mBottomShowProgressThumbDrawable;
        if (drawable2 != null) {
            this.mProgressBar.setThumb(drawable2);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void onClickUiToggle() {
        ViewGroup viewGroup;
        if (this.mIfCurrentIsFullscreen && this.mLockCurScreen && this.mNeedLockFull) {
            setViewShowState(this.mLockScreen, 0);
            return;
        }
        int i2 = this.mCurrentState;
        if (i2 == 1) {
            ViewGroup viewGroup2 = this.mBottomContainer;
            if (viewGroup2 != null) {
                if (viewGroup2.getVisibility() == 0) {
                    changeUiToPrepareingClear();
                    return;
                } else {
                    changeUiToPreparingShow();
                    return;
                }
            }
            return;
        }
        if (i2 == 2) {
            ViewGroup viewGroup3 = this.mBottomContainer;
            if (viewGroup3 != null) {
                if (viewGroup3.getVisibility() == 0) {
                    changeUiToPlayingClear();
                    return;
                } else {
                    changeUiToPlayingShow();
                    return;
                }
            }
            return;
        }
        if (i2 == 5) {
            ViewGroup viewGroup4 = this.mBottomContainer;
            if (viewGroup4 != null) {
                if (viewGroup4.getVisibility() == 0) {
                    changeUiToPauseClear();
                    return;
                } else {
                    changeUiToPauseShow();
                    return;
                }
            }
            return;
        }
        if (i2 == 6) {
            ViewGroup viewGroup5 = this.mBottomContainer;
            if (viewGroup5 != null) {
                if (viewGroup5.getVisibility() == 0) {
                    changeUiToCompleteClear();
                    return;
                } else {
                    changeUiToCompleteShow();
                    return;
                }
            }
            return;
        }
        if (i2 != 3 || (viewGroup = this.mBottomContainer) == null) {
            return;
        }
        if (viewGroup.getVisibility() == 0) {
            changeUiToPlayingBufferingClear();
        } else {
            changeUiToPlayingBufferingShow();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView, android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        dismissVolumeDialog();
        dismissBrightnessDialog();
    }

    public void restartTimerTask() {
        startProgressTimer();
        startDismissControlViewTimer();
    }

    public void saveFrame(File file, InterfaceC2929e interfaceC2929e) {
        saveFrame(file, false, interfaceC2929e);
    }

    public void setBottomProgressBarDrawable(Drawable drawable) {
        this.mBottomProgressDrawable = drawable;
        ProgressBar progressBar = this.mBottomProgressBar;
        if (progressBar != null) {
            progressBar.setProgressDrawable(drawable);
        }
    }

    public void setBottomShowProgressBarDrawable(Drawable drawable, Drawable drawable2) {
        this.mBottomShowProgressDrawable = drawable;
        this.mBottomShowProgressThumbDrawable = drawable2;
        SeekBar seekBar = this.mProgressBar;
        if (seekBar != null) {
            seekBar.setProgressDrawable(drawable);
            this.mProgressBar.setThumb(drawable2);
        }
    }

    public void setDialogProgressBar(Drawable drawable) {
        this.mDialogProgressBarDrawable = drawable;
    }

    public void setDialogProgressColor(int i2, int i3) {
        this.mDialogProgressHighLightColor = i2;
        this.mDialogProgressNormalColor = i3;
    }

    public void setDialogVolumeProgressBar(Drawable drawable) {
        this.mVolumeProgressDrawable = drawable;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void showBrightnessDialog(float f2) {
        if (this.mBrightnessDialog == null) {
            View inflate = LayoutInflater.from(getActivityContext()).inflate(getBrightnessLayoutId(), (ViewGroup) null);
            if (inflate.findViewById(getBrightnessTextId()) instanceof TextView) {
                this.mBrightnessDialogTv = (TextView) inflate.findViewById(getBrightnessTextId());
            }
            Dialog dialog = new Dialog(getActivityContext(), R$style.video_style_dialog_progress);
            this.mBrightnessDialog = dialog;
            dialog.setContentView(inflate);
            this.mBrightnessDialog.getWindow().addFlags(8);
            this.mBrightnessDialog.getWindow().addFlags(32);
            this.mBrightnessDialog.getWindow().addFlags(16);
            this.mBrightnessDialog.getWindow().getDecorView().setSystemUiVisibility(2);
            this.mBrightnessDialog.getWindow().setLayout(-2, -2);
            WindowManager.LayoutParams attributes = this.mBrightnessDialog.getWindow().getAttributes();
            attributes.gravity = BadgeDrawable.TOP_END;
            attributes.width = getWidth();
            attributes.height = getHeight();
            int[] iArr = new int[2];
            getLocationOnScreen(iArr);
            attributes.x = iArr[0];
            attributes.y = iArr[1];
            this.mBrightnessDialog.getWindow().setAttributes(attributes);
        }
        if (!this.mBrightnessDialog.isShowing()) {
            this.mBrightnessDialog.show();
        }
        TextView textView = this.mBrightnessDialogTv;
        if (textView != null) {
            textView.setText(((int) (f2 * 100.0f)) + "%");
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void showProgressDialog(float f2, String str, int i2, String str2, int i3) {
        ProgressBar progressBar;
        TextView textView;
        TextView textView2;
        if (this.mProgressDialog == null) {
            View inflate = LayoutInflater.from(getActivityContext()).inflate(getProgressDialogLayoutId(), (ViewGroup) null);
            if (inflate.findViewById(getProgressDialogProgressId()) instanceof ProgressBar) {
                ProgressBar progressBar2 = (ProgressBar) inflate.findViewById(getProgressDialogProgressId());
                this.mDialogProgressBar = progressBar2;
                Drawable drawable = this.mDialogProgressBarDrawable;
                if (drawable != null) {
                    progressBar2.setProgressDrawable(drawable);
                }
            }
            if (inflate.findViewById(getProgressDialogCurrentDurationTextId()) instanceof TextView) {
                this.mDialogSeekTime = (TextView) inflate.findViewById(getProgressDialogCurrentDurationTextId());
            }
            if (inflate.findViewById(getProgressDialogAllDurationTextId()) instanceof TextView) {
                this.mDialogTotalTime = (TextView) inflate.findViewById(getProgressDialogAllDurationTextId());
            }
            if (inflate.findViewById(getProgressDialogImageId()) instanceof ImageView) {
                this.mDialogIcon = (ImageView) inflate.findViewById(getProgressDialogImageId());
            }
            Dialog dialog = new Dialog(getActivityContext(), R$style.video_style_dialog_progress);
            this.mProgressDialog = dialog;
            dialog.setContentView(inflate);
            this.mProgressDialog.getWindow().addFlags(8);
            this.mProgressDialog.getWindow().addFlags(32);
            this.mProgressDialog.getWindow().addFlags(16);
            this.mProgressDialog.getWindow().setLayout(getWidth(), getHeight());
            int i4 = this.mDialogProgressNormalColor;
            if (i4 != -11 && (textView2 = this.mDialogTotalTime) != null) {
                textView2.setTextColor(i4);
            }
            int i5 = this.mDialogProgressHighLightColor;
            if (i5 != -11 && (textView = this.mDialogSeekTime) != null) {
                textView.setTextColor(i5);
            }
            WindowManager.LayoutParams attributes = this.mProgressDialog.getWindow().getAttributes();
            attributes.gravity = 48;
            attributes.width = getWidth();
            attributes.height = getHeight();
            int[] iArr = new int[2];
            getLocationOnScreen(iArr);
            attributes.x = iArr[0];
            attributes.y = iArr[1];
            this.mProgressDialog.getWindow().setAttributes(attributes);
        }
        if (!this.mProgressDialog.isShowing()) {
            this.mProgressDialog.show();
        }
        TextView textView3 = this.mDialogSeekTime;
        if (textView3 != null) {
            textView3.setText(str);
        }
        TextView textView4 = this.mDialogTotalTime;
        if (textView4 != null) {
            textView4.setText(" / " + str2);
        }
        if (i3 > 0 && (progressBar = this.mDialogProgressBar) != null) {
            progressBar.setProgress((i2 * 100) / i3);
        }
        if (f2 > 0.0f) {
            ImageView imageView = this.mDialogIcon;
            if (imageView != null) {
                imageView.setBackgroundResource(R$drawable.video_forward_icon);
                return;
            }
            return;
        }
        ImageView imageView2 = this.mDialogIcon;
        if (imageView2 != null) {
            imageView2.setBackgroundResource(R$drawable.video_backward_icon);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void showVolumeDialog(float f2, int i2) {
        if (this.mVolumeDialog == null) {
            View inflate = LayoutInflater.from(getActivityContext()).inflate(getVolumeLayoutId(), (ViewGroup) null);
            if (inflate.findViewById(getVolumeProgressId()) instanceof ProgressBar) {
                ProgressBar progressBar = (ProgressBar) inflate.findViewById(getVolumeProgressId());
                this.mDialogVolumeProgressBar = progressBar;
                Drawable drawable = this.mVolumeProgressDrawable;
                if (drawable != null && progressBar != null) {
                    progressBar.setProgressDrawable(drawable);
                }
            }
            Dialog dialog = new Dialog(getActivityContext(), R$style.video_style_dialog_progress);
            this.mVolumeDialog = dialog;
            dialog.setContentView(inflate);
            this.mVolumeDialog.getWindow().addFlags(8);
            this.mVolumeDialog.getWindow().addFlags(32);
            this.mVolumeDialog.getWindow().addFlags(16);
            this.mVolumeDialog.getWindow().setLayout(-2, -2);
            WindowManager.LayoutParams attributes = this.mVolumeDialog.getWindow().getAttributes();
            attributes.gravity = BadgeDrawable.TOP_START;
            attributes.width = getWidth();
            attributes.height = getHeight();
            int[] iArr = new int[2];
            getLocationOnScreen(iArr);
            attributes.x = iArr[0];
            attributes.y = iArr[1];
            this.mVolumeDialog.getWindow().setAttributes(attributes);
        }
        if (!this.mVolumeDialog.isShowing()) {
            this.mVolumeDialog.show();
        }
        ProgressBar progressBar2 = this.mDialogVolumeProgressBar;
        if (progressBar2 != null) {
            progressBar2.setProgress(i2);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoControlView
    public void showWifiDialog() {
        if (!NetworkUtils.isAvailable(this.mContext)) {
            startPlayLogic();
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getActivityContext());
        builder.setMessage(getResources().getString(R$string.tips_not_wifi));
        builder.setPositiveButton(getResources().getString(R$string.tips_not_wifi_confirm), new DialogInterface.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer.1
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialogInterface, int i2) {
                dialogInterface.dismiss();
                StandardGSYVideoPlayer.this.startPlayLogic();
            }
        });
        builder.setNegativeButton(getResources().getString(R$string.tips_not_wifi_cancel), new DialogInterface.OnClickListener() { // from class: com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer.2
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialogInterface, int i2) {
                dialogInterface.dismiss();
            }
        });
        builder.create().show();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoView
    public void startPlayLogic() {
        if (this.mVideoAllCallBack != null) {
            Debuger.printfLog("onClickStartThumb");
            this.mVideoAllCallBack.onClickStartThumb(this.mOriginUrl, this.mTitle, this);
        }
        prepareVideo();
        startDismissControlViewTimer();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer
    public GSYBaseVideoPlayer startWindowFullscreen(Context context, boolean z, boolean z2) {
        GSYBaseVideoPlayer startWindowFullscreen = super.startWindowFullscreen(context, z, z2);
        if (startWindowFullscreen != null) {
            StandardGSYVideoPlayer standardGSYVideoPlayer = (StandardGSYVideoPlayer) startWindowFullscreen;
            standardGSYVideoPlayer.setLockClickListener(this.mLockClickListener);
            standardGSYVideoPlayer.setNeedLockFull(isNeedLockFull());
            initFullUI(standardGSYVideoPlayer);
        }
        return startWindowFullscreen;
    }

    public void taskShotPic(InterfaceC2928d interfaceC2928d) {
        taskShotPic(interfaceC2928d, false);
    }

    public void updateStartImage() {
        View view = this.mStartButton;
        if (!(view instanceof ENPlayView)) {
            if (view instanceof ImageView) {
                ImageView imageView = (ImageView) view;
                int i2 = this.mCurrentState;
                if (i2 == 2) {
                    imageView.setImageResource(R$drawable.video_click_pause_selector);
                    return;
                } else if (i2 == 7) {
                    imageView.setImageResource(R$drawable.video_click_error_selector);
                    return;
                } else {
                    imageView.setImageResource(R$drawable.video_click_play_selector);
                    return;
                }
            }
            return;
        }
        ENPlayView eNPlayView = (ENPlayView) view;
        eNPlayView.setDuration(CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION);
        int i3 = this.mCurrentState;
        if (i3 != 2) {
            if (i3 == 7) {
                eNPlayView.m5647b();
                return;
            } else {
                eNPlayView.m5647b();
                return;
            }
        }
        if (eNPlayView.f12776c == 0) {
            return;
        }
        eNPlayView.f12776c = 0;
        ValueAnimator ofFloat = ValueAnimator.ofFloat(1.0f, 100.0f);
        ofFloat.setDuration(eNPlayView.f12791s);
        ofFloat.setInterpolator(new AnticipateInterpolator());
        ofFloat.addUpdateListener(new C4367c(eNPlayView));
        if (ofFloat.isRunning()) {
            return;
        }
        ofFloat.start();
    }

    public void saveFrame(File file, boolean z, InterfaceC2929e interfaceC2929e) {
        InterfaceC2944a interfaceC2944a;
        if (getCurrentPlayer().getRenderProxy() == null || (interfaceC2944a = getCurrentPlayer().getRenderProxy().f8046a) == null) {
            return;
        }
        interfaceC2944a.mo3411d(file, z, interfaceC2929e);
    }

    public void taskShotPic(InterfaceC2928d interfaceC2928d, boolean z) {
        InterfaceC2944a interfaceC2944a;
        if (getCurrentPlayer().getRenderProxy() == null || (interfaceC2944a = getCurrentPlayer().getRenderProxy().f8046a) == null) {
            return;
        }
        interfaceC2944a.mo3409b(interfaceC2928d, z);
    }

    public StandardGSYVideoPlayer(Context context) {
        super(context);
        this.mDialogProgressHighLightColor = -11;
        this.mDialogProgressNormalColor = -11;
    }

    public StandardGSYVideoPlayer(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.mDialogProgressHighLightColor = -11;
        this.mDialogProgressNormalColor = -11;
    }
}
