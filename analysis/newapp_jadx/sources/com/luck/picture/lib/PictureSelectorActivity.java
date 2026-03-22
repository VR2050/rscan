package com.luck.picture.lib;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.media.MediaPlayer;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Parcelable;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.SimpleItemAnimator;
import com.luck.picture.lib.PictureSelectorActivity;
import com.luck.picture.lib.adapter.PictureImageGridAdapter;
import com.luck.picture.lib.animators.AlphaInAnimationAdapter;
import com.luck.picture.lib.animators.SlideInBottomAnimationAdapter;
import com.luck.picture.lib.config.PictureConfig;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.decoration.GridSpacingItemDecoration;
import com.luck.picture.lib.dialog.PhotoItemSelectedDialog;
import com.luck.picture.lib.dialog.PictureCustomDialog;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.entity.LocalMediaFolder;
import com.luck.picture.lib.listener.OnAlbumItemClickListener;
import com.luck.picture.lib.listener.OnCustomCameraInterfaceListener;
import com.luck.picture.lib.listener.OnCustomImagePreviewCallback;
import com.luck.picture.lib.listener.OnItemClickListener;
import com.luck.picture.lib.listener.OnPhotoSelectChangedListener;
import com.luck.picture.lib.listener.OnQueryDataResultListener;
import com.luck.picture.lib.listener.OnRecyclerViewPreloadMoreListener;
import com.luck.picture.lib.listener.OnResultCallbackListener;
import com.luck.picture.lib.listener.OnVideoSelectedPlayCallback;
import com.luck.picture.lib.manager.UCropManager;
import com.luck.picture.lib.model.LocalMediaLoader;
import com.luck.picture.lib.model.LocalMediaPageLoader;
import com.luck.picture.lib.observable.ImagesObservable;
import com.luck.picture.lib.permissions.PermissionChecker;
import com.luck.picture.lib.style.PictureParameterStyle;
import com.luck.picture.lib.style.PictureSelectorUIStyle;
import com.luck.picture.lib.thread.PictureThreadUtils;
import com.luck.picture.lib.tools.AttrsUtils;
import com.luck.picture.lib.tools.BitmapUtils;
import com.luck.picture.lib.tools.DateUtils;
import com.luck.picture.lib.tools.DoubleUtils;
import com.luck.picture.lib.tools.JumpUtils;
import com.luck.picture.lib.tools.MediaUtils;
import com.luck.picture.lib.tools.PictureFileUtils;
import com.luck.picture.lib.tools.ScreenUtils;
import com.luck.picture.lib.tools.SdkVersionUtils;
import com.luck.picture.lib.tools.StringUtils;
import com.luck.picture.lib.tools.ToastUtils;
import com.luck.picture.lib.tools.ValueOf;
import com.luck.picture.lib.widget.FolderPopWindow;
import com.luck.picture.lib.widget.RecyclerPreloadView;
import com.yalantis.ucrop.UCrop;
import com.yalantis.ucrop.model.CutInfo;
import com.yalantis.ucrop.view.CropImageView;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public class PictureSelectorActivity extends PictureBaseActivity implements View.OnClickListener, OnAlbumItemClickListener, OnPhotoSelectChangedListener<LocalMedia>, OnItemClickListener, OnRecyclerViewPreloadMoreListener {
    private static final String TAG = PictureSelectorActivity.class.getSimpleName();
    private int allFolderSize;
    public PictureCustomDialog audioDialog;
    public FolderPopWindow folderWindow;
    public boolean isEnterSetting;
    public PictureImageGridAdapter mAdapter;
    public RelativeLayout mBottomLayout;
    public CheckBox mCbOriginal;
    public ImageView mIvArrow;
    public ImageView mIvPictureLeftBack;
    private int mOpenCameraCount;
    public RecyclerPreloadView mRecyclerView;
    public View mTitleBar;
    public TextView mTvEmpty;
    public TextView mTvMusicStatus;
    public TextView mTvMusicTime;
    public TextView mTvMusicTotal;
    public TextView mTvPictureImgNum;
    public TextView mTvPictureOk;
    public TextView mTvPicturePreview;
    public TextView mTvPictureRight;
    public TextView mTvPictureTitle;
    public TextView mTvPlayPause;
    public TextView mTvQuit;
    public TextView mTvStop;
    public MediaPlayer mediaPlayer;
    public SeekBar musicSeekBar;
    public int oldCurrentListSize;
    public View viewClickMask;
    public Animation animation = null;
    public boolean isStartAnimation = false;
    public boolean isPlayAudio = false;
    private long intervalClickTime = 0;
    public Runnable mRunnable = new Runnable() { // from class: com.luck.picture.lib.PictureSelectorActivity.4
        @Override // java.lang.Runnable
        public void run() {
            try {
                PictureSelectorActivity pictureSelectorActivity = PictureSelectorActivity.this;
                if (pictureSelectorActivity.mediaPlayer != null) {
                    pictureSelectorActivity.mTvMusicTime.setText(DateUtils.formatDurationTime(r1.getCurrentPosition()));
                    PictureSelectorActivity pictureSelectorActivity2 = PictureSelectorActivity.this;
                    pictureSelectorActivity2.musicSeekBar.setProgress(pictureSelectorActivity2.mediaPlayer.getCurrentPosition());
                    PictureSelectorActivity pictureSelectorActivity3 = PictureSelectorActivity.this;
                    pictureSelectorActivity3.musicSeekBar.setMax(pictureSelectorActivity3.mediaPlayer.getDuration());
                    PictureSelectorActivity.this.mTvMusicTotal.setText(DateUtils.formatDurationTime(r0.mediaPlayer.getDuration()));
                    PictureSelectorActivity pictureSelectorActivity4 = PictureSelectorActivity.this;
                    Handler handler = pictureSelectorActivity4.mHandler;
                    if (handler != null) {
                        handler.postDelayed(pictureSelectorActivity4.mRunnable, 200L);
                    }
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    };

    public class AudioOnClick implements View.OnClickListener {
        private String path;

        public AudioOnClick(String str) {
            this.path = str;
        }

        /* renamed from: a */
        public /* synthetic */ void m4531a() {
            PictureSelectorActivity.this.stop(this.path);
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            Handler handler;
            int id = view.getId();
            if (id == C3979R.id.tv_PlayPause) {
                PictureSelectorActivity.this.playAudio();
            }
            if (id == C3979R.id.tv_Stop) {
                PictureSelectorActivity pictureSelectorActivity = PictureSelectorActivity.this;
                pictureSelectorActivity.mTvMusicStatus.setText(pictureSelectorActivity.getString(C3979R.string.picture_stop_audio));
                PictureSelectorActivity pictureSelectorActivity2 = PictureSelectorActivity.this;
                pictureSelectorActivity2.mTvPlayPause.setText(pictureSelectorActivity2.getString(C3979R.string.picture_play_audio));
                PictureSelectorActivity.this.stop(this.path);
            }
            if (id != C3979R.id.tv_Quit || (handler = PictureSelectorActivity.this.mHandler) == null) {
                return;
            }
            handler.postDelayed(new Runnable() { // from class: b.t.a.a.w
                @Override // java.lang.Runnable
                public final void run() {
                    PictureSelectorActivity.AudioOnClick.this.m4531a();
                }
            }, 30L);
            try {
                PictureCustomDialog pictureCustomDialog = PictureSelectorActivity.this.audioDialog;
                if (pictureCustomDialog != null && pictureCustomDialog.isShowing()) {
                    PictureSelectorActivity.this.audioDialog.dismiss();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            PictureSelectorActivity pictureSelectorActivity3 = PictureSelectorActivity.this;
            pictureSelectorActivity3.mHandler.removeCallbacks(pictureSelectorActivity3.mRunnable);
        }
    }

    private void AudioDialog(final String str) {
        if (isFinishing()) {
            return;
        }
        PictureCustomDialog pictureCustomDialog = new PictureCustomDialog(getContext(), C3979R.layout.picture_audio_dialog);
        this.audioDialog = pictureCustomDialog;
        if (pictureCustomDialog.getWindow() != null) {
            this.audioDialog.getWindow().setWindowAnimations(C3979R.style.Picture_Theme_Dialog_AudioStyle);
        }
        this.mTvMusicStatus = (TextView) this.audioDialog.findViewById(C3979R.id.tv_musicStatus);
        this.mTvMusicTime = (TextView) this.audioDialog.findViewById(C3979R.id.tv_musicTime);
        this.musicSeekBar = (SeekBar) this.audioDialog.findViewById(C3979R.id.musicSeekBar);
        this.mTvMusicTotal = (TextView) this.audioDialog.findViewById(C3979R.id.tv_musicTotal);
        this.mTvPlayPause = (TextView) this.audioDialog.findViewById(C3979R.id.tv_PlayPause);
        this.mTvStop = (TextView) this.audioDialog.findViewById(C3979R.id.tv_Stop);
        this.mTvQuit = (TextView) this.audioDialog.findViewById(C3979R.id.tv_Quit);
        Handler handler = this.mHandler;
        if (handler != null) {
            handler.postDelayed(new Runnable() { // from class: b.t.a.a.c0
                @Override // java.lang.Runnable
                public final void run() {
                    PictureSelectorActivity.this.m4527a(str);
                }
            }, 30L);
        }
        this.mTvPlayPause.setOnClickListener(new AudioOnClick(str));
        this.mTvStop.setOnClickListener(new AudioOnClick(str));
        this.mTvQuit.setOnClickListener(new AudioOnClick(str));
        this.musicSeekBar.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() { // from class: com.luck.picture.lib.PictureSelectorActivity.3
            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onProgressChanged(SeekBar seekBar, int i2, boolean z) {
                if (z) {
                    PictureSelectorActivity.this.mediaPlayer.seekTo(i2);
                }
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStartTrackingTouch(SeekBar seekBar) {
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStopTrackingTouch(SeekBar seekBar) {
            }
        });
        this.audioDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: b.t.a.a.v
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                final PictureSelectorActivity pictureSelectorActivity = PictureSelectorActivity.this;
                final String str2 = str;
                Handler handler2 = pictureSelectorActivity.mHandler;
                if (handler2 != null) {
                    handler2.removeCallbacks(pictureSelectorActivity.mRunnable);
                }
                new Handler().postDelayed(new Runnable() { // from class: b.t.a.a.t
                    @Override // java.lang.Runnable
                    public final void run() {
                        PictureSelectorActivity.this.stop(str2);
                    }
                }, 30L);
                try {
                    PictureCustomDialog pictureCustomDialog2 = pictureSelectorActivity.audioDialog;
                    if (pictureCustomDialog2 == null || !pictureCustomDialog2.isShowing()) {
                        return;
                    }
                    pictureSelectorActivity.audioDialog.dismiss();
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            }
        });
        Handler handler2 = this.mHandler;
        if (handler2 != null) {
            handler2.post(this.mRunnable);
        }
        this.audioDialog.show();
    }

    private void bothMimeTypeWith(boolean z, List<LocalMedia> list) {
        int i2 = 0;
        LocalMedia localMedia = list.size() > 0 ? list.get(0) : null;
        if (localMedia == null) {
            return;
        }
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (!pictureSelectionConfig.enableCrop) {
            if (!pictureSelectionConfig.isCompress) {
                onResult(list);
                return;
            }
            int size = list.size();
            int i3 = 0;
            while (true) {
                if (i3 >= size) {
                    break;
                }
                if (PictureMimeType.isHasImage(list.get(i3).getMimeType())) {
                    i2 = 1;
                    break;
                }
                i3++;
            }
            if (i2 <= 0) {
                onResult(list);
                return;
            } else {
                compressImage(list);
                return;
            }
        }
        if (pictureSelectionConfig.selectionMode == 1 && z) {
            pictureSelectionConfig.originalPath = localMedia.getPath();
            UCropManager.ofCrop(this, this.config.originalPath, localMedia.getMimeType());
            return;
        }
        ArrayList arrayList = new ArrayList();
        int size2 = list.size();
        int i4 = 0;
        while (i2 < size2) {
            LocalMedia localMedia2 = list.get(i2);
            if (localMedia2 != null && !TextUtils.isEmpty(localMedia2.getPath())) {
                if (PictureMimeType.isHasImage(localMedia2.getMimeType())) {
                    i4++;
                }
                CutInfo cutInfo = new CutInfo();
                cutInfo.setId(localMedia2.getId());
                cutInfo.setPath(localMedia2.getPath());
                cutInfo.setImageWidth(localMedia2.getWidth());
                cutInfo.setImageHeight(localMedia2.getHeight());
                cutInfo.setMimeType(localMedia2.getMimeType());
                cutInfo.setDuration(localMedia2.getDuration());
                cutInfo.setRealPath(localMedia2.getRealPath());
                arrayList.add(cutInfo);
            }
            i2++;
        }
        if (i4 <= 0) {
            onResult(list);
        } else {
            UCropManager.ofCrop(this, arrayList);
        }
    }

    private boolean checkVideoLegitimacy(LocalMedia localMedia) {
        if (!PictureMimeType.isHasVideo(localMedia.getMimeType())) {
            return true;
        }
        PictureSelectionConfig pictureSelectionConfig = this.config;
        int i2 = pictureSelectionConfig.videoMinSecond;
        if (i2 <= 0 || pictureSelectionConfig.videoMaxSecond <= 0) {
            if (i2 > 0) {
                long duration = localMedia.getDuration();
                int i3 = this.config.videoMinSecond;
                if (duration >= i3) {
                    return true;
                }
                showPromptDialog(getString(C3979R.string.picture_choose_min_seconds, new Object[]{Integer.valueOf(i3 / 1000)}));
            } else {
                if (pictureSelectionConfig.videoMaxSecond <= 0) {
                    return true;
                }
                long duration2 = localMedia.getDuration();
                int i4 = this.config.videoMaxSecond;
                if (duration2 <= i4) {
                    return true;
                }
                showPromptDialog(getString(C3979R.string.picture_choose_max_seconds, new Object[]{Integer.valueOf(i4 / 1000)}));
            }
        } else {
            if (localMedia.getDuration() >= this.config.videoMinSecond && localMedia.getDuration() <= this.config.videoMaxSecond) {
                return true;
            }
            showPromptDialog(getString(C3979R.string.picture_choose_limit_seconds, new Object[]{Integer.valueOf(this.config.videoMinSecond / 1000), Integer.valueOf(this.config.videoMaxSecond / 1000)}));
        }
        return false;
    }

    private void dispatchHandleCamera(final Intent intent) {
        PictureSelectionConfig pictureSelectionConfig = intent != null ? (PictureSelectionConfig) intent.getParcelableExtra(PictureConfig.EXTRA_CONFIG) : null;
        if (pictureSelectionConfig != null) {
            this.config = pictureSelectionConfig;
        }
        final boolean z = this.config.chooseMode == PictureMimeType.ofAudio();
        PictureSelectionConfig pictureSelectionConfig2 = this.config;
        pictureSelectionConfig2.cameraPath = z ? getAudioPath(intent) : pictureSelectionConfig2.cameraPath;
        if (TextUtils.isEmpty(this.config.cameraPath)) {
            return;
        }
        showPleaseDialog();
        PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<LocalMedia>() { // from class: com.luck.picture.lib.PictureSelectorActivity.5
            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            public LocalMedia doInBackground() {
                LocalMedia localMedia = new LocalMedia();
                boolean z2 = z;
                String str = z2 ? PictureMimeType.MIME_TYPE_AUDIO : "";
                long j2 = 0;
                if (!z2) {
                    if (PictureMimeType.isContent(PictureSelectorActivity.this.config.cameraPath)) {
                        String path = PictureFileUtils.getPath(PictureSelectorActivity.this.getContext(), Uri.parse(PictureSelectorActivity.this.config.cameraPath));
                        if (!TextUtils.isEmpty(path)) {
                            File file = new File(path);
                            String mimeType = PictureMimeType.getMimeType(PictureSelectorActivity.this.config.cameraMimeType);
                            localMedia.setSize(file.length());
                            str = mimeType;
                        }
                        if (PictureMimeType.isHasImage(str)) {
                            int[] imageSizeForUrlToAndroidQ = MediaUtils.getImageSizeForUrlToAndroidQ(PictureSelectorActivity.this.getContext(), PictureSelectorActivity.this.config.cameraPath);
                            localMedia.setWidth(imageSizeForUrlToAndroidQ[0]);
                            localMedia.setHeight(imageSizeForUrlToAndroidQ[1]);
                        } else if (PictureMimeType.isHasVideo(str)) {
                            MediaUtils.getVideoSizeForUri(PictureSelectorActivity.this.getContext(), Uri.parse(PictureSelectorActivity.this.config.cameraPath), localMedia);
                            j2 = MediaUtils.extractDuration(PictureSelectorActivity.this.getContext(), SdkVersionUtils.checkedAndroid_Q(), PictureSelectorActivity.this.config.cameraPath);
                        }
                        int lastIndexOf = PictureSelectorActivity.this.config.cameraPath.lastIndexOf("/") + 1;
                        localMedia.setId(lastIndexOf > 0 ? ValueOf.toLong(PictureSelectorActivity.this.config.cameraPath.substring(lastIndexOf)) : -1L);
                        localMedia.setRealPath(path);
                        Intent intent2 = intent;
                        localMedia.setAndroidQToPath(intent2 != null ? intent2.getStringExtra(PictureConfig.EXTRA_MEDIA_PATH) : null);
                    } else {
                        File file2 = new File(PictureSelectorActivity.this.config.cameraPath);
                        str = PictureMimeType.getMimeType(PictureSelectorActivity.this.config.cameraMimeType);
                        localMedia.setSize(file2.length());
                        if (PictureMimeType.isHasImage(str)) {
                            BitmapUtils.rotateImage(PictureFileUtils.readPictureDegree(PictureSelectorActivity.this.getContext(), PictureSelectorActivity.this.config.cameraPath), PictureSelectorActivity.this.config.cameraPath);
                            int[] imageSizeForUrl = MediaUtils.getImageSizeForUrl(PictureSelectorActivity.this.config.cameraPath);
                            localMedia.setWidth(imageSizeForUrl[0]);
                            localMedia.setHeight(imageSizeForUrl[1]);
                        } else if (PictureMimeType.isHasVideo(str)) {
                            int[] videoSizeForUrl = MediaUtils.getVideoSizeForUrl(PictureSelectorActivity.this.config.cameraPath);
                            j2 = MediaUtils.extractDuration(PictureSelectorActivity.this.getContext(), SdkVersionUtils.checkedAndroid_Q(), PictureSelectorActivity.this.config.cameraPath);
                            localMedia.setWidth(videoSizeForUrl[0]);
                            localMedia.setHeight(videoSizeForUrl[1]);
                        }
                        localMedia.setId(System.currentTimeMillis());
                    }
                    localMedia.setPath(PictureSelectorActivity.this.config.cameraPath);
                    localMedia.setDuration(j2);
                    localMedia.setMimeType(str);
                    if (SdkVersionUtils.checkedAndroid_Q() && PictureMimeType.isHasVideo(localMedia.getMimeType())) {
                        localMedia.setParentFolderName(Environment.DIRECTORY_MOVIES);
                    } else {
                        localMedia.setParentFolderName(PictureMimeType.CAMERA);
                    }
                    localMedia.setChooseModel(PictureSelectorActivity.this.config.chooseMode);
                    localMedia.setBucketId(MediaUtils.getCameraFirstBucketId(PictureSelectorActivity.this.getContext()));
                    Context context = PictureSelectorActivity.this.getContext();
                    PictureSelectionConfig pictureSelectionConfig3 = PictureSelectorActivity.this.config;
                    MediaUtils.setOrientationSynchronous(context, localMedia, pictureSelectionConfig3.isAndroidQChangeWH, pictureSelectionConfig3.isAndroidQChangeVideoWH);
                }
                return localMedia;
            }

            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            public void onSuccess(LocalMedia localMedia) {
                int dCIMLastImageId;
                PictureSelectorActivity.this.dismissDialog();
                if (!SdkVersionUtils.checkedAndroid_Q()) {
                    PictureSelectorActivity pictureSelectorActivity = PictureSelectorActivity.this;
                    if (pictureSelectorActivity.config.isFallbackVersion3) {
                        new PictureMediaScannerConnection(pictureSelectorActivity.getContext(), PictureSelectorActivity.this.config.cameraPath);
                    } else {
                        pictureSelectorActivity.sendBroadcast(new Intent("android.intent.action.MEDIA_SCANNER_SCAN_FILE", Uri.fromFile(new File(PictureSelectorActivity.this.config.cameraPath))));
                    }
                }
                PictureSelectorActivity.this.notifyAdapterData(localMedia);
                if (SdkVersionUtils.checkedAndroid_Q() || !PictureMimeType.isHasImage(localMedia.getMimeType()) || (dCIMLastImageId = MediaUtils.getDCIMLastImageId(PictureSelectorActivity.this.getContext())) == -1) {
                    return;
                }
                MediaUtils.removeMedia(PictureSelectorActivity.this.getContext(), dCIMLastImageId);
            }
        });
    }

    private void dispatchHandleMultiple(LocalMedia localMedia) {
        int i2;
        List<LocalMedia> selectedData = this.mAdapter.getSelectedData();
        int size = selectedData.size();
        String mimeType = size > 0 ? selectedData.get(0).getMimeType() : "";
        boolean isMimeTypeSame = PictureMimeType.isMimeTypeSame(mimeType, localMedia.getMimeType());
        if (!this.config.isWithVideoImage) {
            if (!PictureMimeType.isHasVideo(mimeType) || (i2 = this.config.maxVideoSelectNum) <= 0) {
                if (size >= this.config.maxSelectNum) {
                    showPromptDialog(StringUtils.getMsg(getContext(), mimeType, this.config.maxSelectNum));
                    return;
                } else {
                    if (isMimeTypeSame || size == 0) {
                        selectedData.add(0, localMedia);
                        this.mAdapter.bindSelectData(selectedData);
                        return;
                    }
                    return;
                }
            }
            if (size >= i2) {
                showPromptDialog(StringUtils.getMsg(getContext(), mimeType, this.config.maxVideoSelectNum));
                return;
            } else {
                if ((isMimeTypeSame || size == 0) && selectedData.size() < this.config.maxVideoSelectNum) {
                    selectedData.add(0, localMedia);
                    this.mAdapter.bindSelectData(selectedData);
                    return;
                }
                return;
            }
        }
        int i3 = 0;
        for (int i4 = 0; i4 < size; i4++) {
            if (PictureMimeType.isHasVideo(selectedData.get(i4).getMimeType())) {
                i3++;
            }
        }
        if (!PictureMimeType.isHasVideo(localMedia.getMimeType())) {
            if (selectedData.size() >= this.config.maxSelectNum) {
                showPromptDialog(StringUtils.getMsg(getContext(), localMedia.getMimeType(), this.config.maxSelectNum));
                return;
            } else {
                selectedData.add(0, localMedia);
                this.mAdapter.bindSelectData(selectedData);
                return;
            }
        }
        int i5 = this.config.maxVideoSelectNum;
        if (i5 <= 0) {
            showPromptDialog(getString(C3979R.string.picture_rule));
        } else if (i3 >= i5) {
            showPromptDialog(getString(C3979R.string.picture_message_max_num, new Object[]{Integer.valueOf(i5)}));
        } else {
            selectedData.add(0, localMedia);
            this.mAdapter.bindSelectData(selectedData);
        }
    }

    private void dispatchHandleSingle(LocalMedia localMedia) {
        if (this.config.isSingleDirectReturn) {
            List<LocalMedia> selectedData = this.mAdapter.getSelectedData();
            selectedData.add(localMedia);
            this.mAdapter.bindSelectData(selectedData);
            singleDirectReturnCameraHandleResult(localMedia.getMimeType());
            return;
        }
        List<LocalMedia> selectedData2 = this.mAdapter.getSelectedData();
        if (PictureMimeType.isMimeTypeSame(selectedData2.size() > 0 ? selectedData2.get(0).getMimeType() : "", localMedia.getMimeType()) || selectedData2.size() == 0) {
            singleRadioMediaImage();
            selectedData2.add(localMedia);
            this.mAdapter.bindSelectData(selectedData2);
        }
    }

    private int getPageLimit() {
        if (ValueOf.toInt(this.mTvPictureTitle.getTag(C3979R.id.view_tag)) != -1) {
            return this.config.pageSize;
        }
        int i2 = this.mOpenCameraCount;
        int i3 = i2 > 0 ? this.config.pageSize - i2 : this.config.pageSize;
        this.mOpenCameraCount = 0;
        return i3;
    }

    private void hideDataNull() {
        if (this.mTvEmpty.getVisibility() == 0) {
            this.mTvEmpty.setVisibility(8);
        }
    }

    private void initPageModel(List<LocalMediaFolder> list) {
        if (list == null) {
            showDataNull(getString(C3979R.string.picture_data_exception), C3979R.drawable.picture_icon_data_error);
            dismissDialog();
            return;
        }
        this.folderWindow.bindFolder(list);
        this.mPage = 1;
        LocalMediaFolder folder = this.folderWindow.getFolder(0);
        this.mTvPictureTitle.setTag(C3979R.id.view_count_tag, Integer.valueOf(folder != null ? folder.getImageNum() : 0));
        this.mTvPictureTitle.setTag(C3979R.id.view_index_tag, 0);
        long bucketId = folder != null ? folder.getBucketId() : -1L;
        this.mRecyclerView.setEnabledLoadMore(true);
        LocalMediaPageLoader.getInstance(getContext()).loadPageMediaData(bucketId, this.mPage, new OnQueryDataResultListener() { // from class: b.t.a.a.a0
            @Override // com.luck.picture.lib.listener.OnQueryDataResultListener
            public final void onComplete(List list2, int i2, boolean z) {
                PictureSelectorActivity.this.m4528b(list2, i2, z);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initPlayer, reason: merged with bridge method [inline-methods] */
    public void m4527a(String str) {
        MediaPlayer mediaPlayer = new MediaPlayer();
        this.mediaPlayer = mediaPlayer;
        try {
            mediaPlayer.setDataSource(str);
            this.mediaPlayer.prepare();
            this.mediaPlayer.setLooping(true);
            playAudio();
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void initStandardModel(List<LocalMediaFolder> list) {
        if (list == null) {
            showDataNull(getString(C3979R.string.picture_data_exception), C3979R.drawable.picture_icon_data_error);
        } else if (list.size() > 0) {
            this.folderWindow.bindFolder(list);
            LocalMediaFolder localMediaFolder = list.get(0);
            localMediaFolder.setChecked(true);
            this.mTvPictureTitle.setTag(C3979R.id.view_count_tag, Integer.valueOf(localMediaFolder.getImageNum()));
            List<LocalMedia> data = localMediaFolder.getData();
            PictureImageGridAdapter pictureImageGridAdapter = this.mAdapter;
            if (pictureImageGridAdapter != null) {
                int size = pictureImageGridAdapter.getSize();
                int size2 = data.size();
                int i2 = this.oldCurrentListSize + size;
                this.oldCurrentListSize = i2;
                if (size2 >= size) {
                    if (size <= 0 || size >= size2 || i2 == size2) {
                        this.mAdapter.bindData(data);
                    } else {
                        this.mAdapter.getData().addAll(data);
                        LocalMedia localMedia = this.mAdapter.getData().get(0);
                        localMediaFolder.setFirstImagePath(localMedia.getPath());
                        localMediaFolder.getData().add(0, localMedia);
                        localMediaFolder.setCheckedNum(1);
                        localMediaFolder.setImageNum(localMediaFolder.getImageNum() + 1);
                        updateMediaFolder(this.folderWindow.getFolderData(), localMedia);
                    }
                }
                if (this.mAdapter.isDataEmpty()) {
                    showDataNull(getString(C3979R.string.picture_empty), C3979R.drawable.picture_icon_no_data);
                } else {
                    hideDataNull();
                }
            }
        } else {
            showDataNull(getString(C3979R.string.picture_empty), C3979R.drawable.picture_icon_no_data);
        }
        dismissDialog();
    }

    private boolean isAddSameImp(int i2) {
        int i3;
        return i2 != 0 && (i3 = this.allFolderSize) > 0 && i3 < i2;
    }

    private boolean isCurrentCacheFolderData(int i2) {
        this.mTvPictureTitle.setTag(C3979R.id.view_index_tag, Integer.valueOf(i2));
        LocalMediaFolder folder = this.folderWindow.getFolder(i2);
        if (folder == null || folder.getData() == null || folder.getData().size() <= 0) {
            return false;
        }
        this.mAdapter.bindData(folder.getData());
        this.mPage = folder.getCurrentDataPage();
        this.isHasMore = folder.isHasMore();
        this.mRecyclerView.smoothScrollToPosition(0);
        return true;
    }

    private boolean isLocalMediaSame(LocalMedia localMedia) {
        LocalMedia item = this.mAdapter.getItem(0);
        if (item != null && localMedia != null) {
            if (item.getPath().equals(localMedia.getPath())) {
                return true;
            }
            if (PictureMimeType.isContent(localMedia.getPath()) && PictureMimeType.isContent(item.getPath()) && !TextUtils.isEmpty(localMedia.getPath()) && !TextUtils.isEmpty(item.getPath()) && localMedia.getPath().substring(localMedia.getPath().lastIndexOf("/") + 1).equals(item.getPath().substring(item.getPath().lastIndexOf("/") + 1))) {
                return true;
            }
        }
        return false;
    }

    private void isNumComplete(boolean z) {
        if (z) {
            initCompleteText(0);
        }
    }

    private void loadAllMediaData() {
        if (PermissionChecker.checkSelfPermission(this, "android.permission.READ_EXTERNAL_STORAGE") && PermissionChecker.checkSelfPermission(this, "android.permission.WRITE_EXTERNAL_STORAGE")) {
            readLocalMedia();
        } else {
            PermissionChecker.requestPermissions(this, new String[]{"android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"}, 1);
        }
    }

    private void loadMoreData() {
        if (this.mAdapter == null || !this.isHasMore) {
            return;
        }
        this.mPage++;
        final long j2 = ValueOf.toLong(this.mTvPictureTitle.getTag(C3979R.id.view_tag));
        LocalMediaPageLoader.getInstance(getContext()).loadPageMediaData(j2, this.mPage, getPageLimit(), new OnQueryDataResultListener() { // from class: b.t.a.a.d0
            @Override // com.luck.picture.lib.listener.OnQueryDataResultListener
            public final void onComplete(List list, int i2, boolean z) {
                PictureSelectorActivity.this.m4529c(j2, list, i2, z);
            }
        });
    }

    private void manualSaveFolder(LocalMedia localMedia) {
        LocalMediaFolder localMediaFolder;
        try {
            boolean isEmpty = this.folderWindow.isEmpty();
            int imageNum = this.folderWindow.getFolder(0) != null ? this.folderWindow.getFolder(0).getImageNum() : 0;
            if (isEmpty) {
                createNewFolder(this.folderWindow.getFolderData());
                localMediaFolder = this.folderWindow.getFolderData().size() > 0 ? this.folderWindow.getFolderData().get(0) : null;
                if (localMediaFolder == null) {
                    localMediaFolder = new LocalMediaFolder();
                    this.folderWindow.getFolderData().add(0, localMediaFolder);
                }
            } else {
                localMediaFolder = this.folderWindow.getFolderData().get(0);
            }
            localMediaFolder.setFirstImagePath(localMedia.getPath());
            localMediaFolder.setData(this.mAdapter.getData());
            localMediaFolder.setBucketId(-1L);
            localMediaFolder.setImageNum(isAddSameImp(imageNum) ? localMediaFolder.getImageNum() : localMediaFolder.getImageNum() + 1);
            LocalMediaFolder imageFolder = getImageFolder(localMedia.getPath(), localMedia.getRealPath(), this.folderWindow.getFolderData());
            if (imageFolder != null) {
                imageFolder.setImageNum(isAddSameImp(imageNum) ? imageFolder.getImageNum() : imageFolder.getImageNum() + 1);
                if (!isAddSameImp(imageNum)) {
                    imageFolder.getData().add(0, localMedia);
                }
                imageFolder.setBucketId(localMedia.getBucketId());
                imageFolder.setFirstImagePath(this.config.cameraPath);
            }
            FolderPopWindow folderPopWindow = this.folderWindow;
            folderPopWindow.bindFolder(folderPopWindow.getFolderData());
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    private void manualSaveFolderForPageModel(LocalMedia localMedia) {
        if (localMedia == null) {
            return;
        }
        int size = this.folderWindow.getFolderData().size();
        boolean z = false;
        LocalMediaFolder localMediaFolder = size > 0 ? this.folderWindow.getFolderData().get(0) : new LocalMediaFolder();
        if (localMediaFolder != null) {
            int imageNum = localMediaFolder.getImageNum();
            localMediaFolder.setFirstImagePath(localMedia.getPath());
            localMediaFolder.setImageNum(isAddSameImp(imageNum) ? localMediaFolder.getImageNum() : localMediaFolder.getImageNum() + 1);
            if (size == 0) {
                localMediaFolder.setName(getString(this.config.chooseMode == PictureMimeType.ofAudio() ? C3979R.string.picture_all_audio : C3979R.string.picture_camera_roll));
                localMediaFolder.setOfAllType(this.config.chooseMode);
                localMediaFolder.setCameraFolder(true);
                localMediaFolder.setChecked(true);
                localMediaFolder.setBucketId(-1L);
                this.folderWindow.getFolderData().add(0, localMediaFolder);
                LocalMediaFolder localMediaFolder2 = new LocalMediaFolder();
                localMediaFolder2.setName(localMedia.getParentFolderName());
                localMediaFolder2.setImageNum(isAddSameImp(imageNum) ? localMediaFolder2.getImageNum() : localMediaFolder2.getImageNum() + 1);
                localMediaFolder2.setFirstImagePath(localMedia.getPath());
                localMediaFolder2.setBucketId(localMedia.getBucketId());
                this.folderWindow.getFolderData().add(this.folderWindow.getFolderData().size(), localMediaFolder2);
            } else {
                String str = (SdkVersionUtils.checkedAndroid_Q() && PictureMimeType.isHasVideo(localMedia.getMimeType())) ? Environment.DIRECTORY_MOVIES : PictureMimeType.CAMERA;
                int i2 = 0;
                while (true) {
                    if (i2 >= size) {
                        break;
                    }
                    LocalMediaFolder localMediaFolder3 = this.folderWindow.getFolderData().get(i2);
                    if (TextUtils.isEmpty(localMediaFolder3.getName()) || !localMediaFolder3.getName().startsWith(str)) {
                        i2++;
                    } else {
                        localMedia.setBucketId(localMediaFolder3.getBucketId());
                        localMediaFolder3.setFirstImagePath(this.config.cameraPath);
                        localMediaFolder3.setImageNum(isAddSameImp(imageNum) ? localMediaFolder3.getImageNum() : localMediaFolder3.getImageNum() + 1);
                        if (localMediaFolder3.getData() != null && localMediaFolder3.getData().size() > 0) {
                            localMediaFolder3.getData().add(0, localMedia);
                        }
                        z = true;
                    }
                }
                if (!z) {
                    LocalMediaFolder localMediaFolder4 = new LocalMediaFolder();
                    localMediaFolder4.setName(localMedia.getParentFolderName());
                    localMediaFolder4.setImageNum(isAddSameImp(imageNum) ? localMediaFolder4.getImageNum() : localMediaFolder4.getImageNum() + 1);
                    localMediaFolder4.setFirstImagePath(localMedia.getPath());
                    localMediaFolder4.setBucketId(localMedia.getBucketId());
                    this.folderWindow.getFolderData().add(localMediaFolder4);
                    sortFolder(this.folderWindow.getFolderData());
                }
            }
            FolderPopWindow folderPopWindow = this.folderWindow;
            folderPopWindow.bindFolder(folderPopWindow.getFolderData());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyAdapterData(LocalMedia localMedia) {
        if (this.mAdapter != null) {
            if (!isAddSameImp(this.folderWindow.getFolder(0) != null ? this.folderWindow.getFolder(0).getImageNum() : 0)) {
                this.mAdapter.getData().add(0, localMedia);
                this.mOpenCameraCount++;
            }
            if (checkVideoLegitimacy(localMedia)) {
                if (this.config.selectionMode == 1) {
                    dispatchHandleSingle(localMedia);
                } else {
                    dispatchHandleMultiple(localMedia);
                }
            }
            this.mAdapter.notifyItemInserted(this.config.isCamera ? 1 : 0);
            PictureImageGridAdapter pictureImageGridAdapter = this.mAdapter;
            pictureImageGridAdapter.notifyItemRangeChanged(this.config.isCamera ? 1 : 0, pictureImageGridAdapter.getSize());
            if (this.config.isPageStrategy) {
                manualSaveFolderForPageModel(localMedia);
            } else {
                manualSaveFolder(localMedia);
            }
            this.mTvEmpty.setVisibility((this.mAdapter.getSize() > 0 || this.config.isSingleDirectReturn) ? 8 : 0);
            if (this.folderWindow.getFolder(0) != null) {
                this.mTvPictureTitle.setTag(C3979R.id.view_count_tag, Integer.valueOf(this.folderWindow.getFolder(0).getImageNum()));
            }
            this.allFolderSize = 0;
        }
    }

    private void onComplete() {
        int i2;
        int i3;
        List<LocalMedia> selectedData = this.mAdapter.getSelectedData();
        int size = selectedData.size();
        LocalMedia localMedia = selectedData.size() > 0 ? selectedData.get(0) : null;
        String mimeType = localMedia != null ? localMedia.getMimeType() : "";
        boolean isHasImage = PictureMimeType.isHasImage(mimeType);
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.isWithVideoImage) {
            int i4 = 0;
            int i5 = 0;
            for (int i6 = 0; i6 < size; i6++) {
                if (PictureMimeType.isHasVideo(selectedData.get(i6).getMimeType())) {
                    i5++;
                } else {
                    i4++;
                }
            }
            PictureSelectionConfig pictureSelectionConfig2 = this.config;
            if (pictureSelectionConfig2.selectionMode == 2) {
                int i7 = pictureSelectionConfig2.minSelectNum;
                if (i7 > 0 && i4 < i7) {
                    showPromptDialog(getString(C3979R.string.picture_min_img_num, new Object[]{Integer.valueOf(i7)}));
                    return;
                }
                int i8 = pictureSelectionConfig2.minVideoSelectNum;
                if (i8 > 0 && i5 < i8) {
                    showPromptDialog(getString(C3979R.string.picture_min_video_num, new Object[]{Integer.valueOf(i8)}));
                    return;
                }
            }
        } else if (pictureSelectionConfig.selectionMode == 2) {
            if (PictureMimeType.isHasImage(mimeType) && (i3 = this.config.minSelectNum) > 0 && size < i3) {
                showPromptDialog(getString(C3979R.string.picture_min_img_num, new Object[]{Integer.valueOf(i3)}));
                return;
            } else if (PictureMimeType.isHasVideo(mimeType) && (i2 = this.config.minVideoSelectNum) > 0 && size < i2) {
                showPromptDialog(getString(C3979R.string.picture_min_video_num, new Object[]{Integer.valueOf(i2)}));
                return;
            }
        }
        PictureSelectionConfig pictureSelectionConfig3 = this.config;
        if (!pictureSelectionConfig3.returnEmpty || size != 0) {
            if (pictureSelectionConfig3.isCheckOriginalImage) {
                onResult(selectedData);
                return;
            } else if (pictureSelectionConfig3.chooseMode == PictureMimeType.ofAll() && this.config.isWithVideoImage) {
                bothMimeTypeWith(isHasImage, selectedData);
                return;
            } else {
                separateMimeTypeWith(isHasImage, selectedData);
                return;
            }
        }
        if (pictureSelectionConfig3.selectionMode == 2) {
            int i9 = pictureSelectionConfig3.minSelectNum;
            if (i9 > 0 && size < i9) {
                showPromptDialog(getString(C3979R.string.picture_min_img_num, new Object[]{Integer.valueOf(i9)}));
                return;
            }
            int i10 = pictureSelectionConfig3.minVideoSelectNum;
            if (i10 > 0 && size < i10) {
                showPromptDialog(getString(C3979R.string.picture_min_video_num, new Object[]{Integer.valueOf(i10)}));
                return;
            }
        }
        OnResultCallbackListener onResultCallbackListener = PictureSelectionConfig.listener;
        if (onResultCallbackListener != null) {
            onResultCallbackListener.onResult(selectedData);
        } else {
            setResult(-1, PictureSelector.putIntentResult(selectedData));
        }
        exit();
    }

    private void onPreview() {
        List<LocalMedia> selectedData = this.mAdapter.getSelectedData();
        ArrayList<? extends Parcelable> arrayList = new ArrayList<>();
        int size = selectedData.size();
        for (int i2 = 0; i2 < size; i2++) {
            arrayList.add(selectedData.get(i2));
        }
        OnCustomImagePreviewCallback onCustomImagePreviewCallback = PictureSelectionConfig.onCustomImagePreviewCallback;
        if (onCustomImagePreviewCallback != null) {
            onCustomImagePreviewCallback.onCustomPreviewCallback(getContext(), selectedData, 0);
            return;
        }
        Bundle bundle = new Bundle();
        bundle.putParcelableArrayList(PictureConfig.EXTRA_PREVIEW_SELECT_LIST, arrayList);
        bundle.putParcelableArrayList(PictureConfig.EXTRA_SELECT_LIST, (ArrayList) selectedData);
        bundle.putBoolean(PictureConfig.EXTRA_BOTTOM_PREVIEW, true);
        bundle.putBoolean(PictureConfig.EXTRA_CHANGE_ORIGINAL, this.config.isCheckOriginalImage);
        bundle.putBoolean(PictureConfig.EXTRA_SHOW_CAMERA, this.mAdapter.isShowCamera());
        bundle.putString(PictureConfig.EXTRA_IS_CURRENT_DIRECTORY, this.mTvPictureTitle.getText().toString());
        Context context = getContext();
        PictureSelectionConfig pictureSelectionConfig = this.config;
        JumpUtils.startPicturePreviewActivity(context, pictureSelectionConfig.isWeChatStyle, bundle, pictureSelectionConfig.selectionMode == 1 ? 69 : UCrop.REQUEST_MULTI_CROP);
        overridePendingTransition(PictureSelectionConfig.windowAnimationStyle.activityPreviewEnterAnimation, C3979R.anim.picture_anim_fade_in);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void playAudio() {
        MediaPlayer mediaPlayer = this.mediaPlayer;
        if (mediaPlayer != null) {
            this.musicSeekBar.setProgress(mediaPlayer.getCurrentPosition());
            this.musicSeekBar.setMax(this.mediaPlayer.getDuration());
        }
        String charSequence = this.mTvPlayPause.getText().toString();
        int i2 = C3979R.string.picture_play_audio;
        if (charSequence.equals(getString(i2))) {
            this.mTvPlayPause.setText(getString(C3979R.string.picture_pause_audio));
            this.mTvMusicStatus.setText(getString(i2));
            playOrPause();
        } else {
            this.mTvPlayPause.setText(getString(i2));
            this.mTvMusicStatus.setText(getString(C3979R.string.picture_pause_audio));
            playOrPause();
        }
        if (this.isPlayAudio) {
            return;
        }
        Handler handler = this.mHandler;
        if (handler != null) {
            handler.post(this.mRunnable);
        }
        this.isPlayAudio = true;
    }

    private void previewCallback(Intent intent) {
        if (intent == null) {
            return;
        }
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.isOriginalControl) {
            pictureSelectionConfig.isCheckOriginalImage = intent.getBooleanExtra(PictureConfig.EXTRA_CHANGE_ORIGINAL, pictureSelectionConfig.isCheckOriginalImage);
            this.mCbOriginal.setChecked(this.config.isCheckOriginalImage);
        }
        ArrayList parcelableArrayListExtra = intent.getParcelableArrayListExtra(PictureConfig.EXTRA_SELECT_LIST);
        if (this.mAdapter == null || parcelableArrayListExtra == null) {
            return;
        }
        char c2 = 0;
        if (intent.getBooleanExtra(PictureConfig.EXTRA_COMPLETE_SELECTED, false)) {
            onChangeData(parcelableArrayListExtra);
            if (this.config.isWithVideoImage) {
                int size = parcelableArrayListExtra.size();
                int i2 = 0;
                while (true) {
                    if (i2 >= size) {
                        break;
                    }
                    if (PictureMimeType.isHasImage(parcelableArrayListExtra.get(i2).getMimeType())) {
                        c2 = 1;
                        break;
                    }
                    i2++;
                }
                if (c2 > 0) {
                    PictureSelectionConfig pictureSelectionConfig2 = this.config;
                    if (pictureSelectionConfig2.isCompress && !pictureSelectionConfig2.isCheckOriginalImage) {
                        compressImage(parcelableArrayListExtra);
                    }
                }
                onResult(parcelableArrayListExtra);
            } else {
                String mimeType = parcelableArrayListExtra.size() > 0 ? parcelableArrayListExtra.get(0).getMimeType() : "";
                if (this.config.isCompress && PictureMimeType.isHasImage(mimeType) && !this.config.isCheckOriginalImage) {
                    compressImage(parcelableArrayListExtra);
                } else {
                    onResult(parcelableArrayListExtra);
                }
            }
        } else {
            this.isStartAnimation = true;
        }
        this.mAdapter.bindSelectData(parcelableArrayListExtra);
        this.mAdapter.notifyDataSetChanged();
    }

    private void separateMimeTypeWith(boolean z, List<LocalMedia> list) {
        LocalMedia localMedia = list.size() > 0 ? list.get(0) : null;
        if (localMedia == null) {
            return;
        }
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (!pictureSelectionConfig.enableCrop || !z) {
            if (pictureSelectionConfig.isCompress && z) {
                compressImage(list);
                return;
            } else {
                onResult(list);
                return;
            }
        }
        if (pictureSelectionConfig.selectionMode == 1) {
            pictureSelectionConfig.originalPath = localMedia.getPath();
            UCropManager.ofCrop(this, this.config.originalPath, localMedia.getMimeType());
            return;
        }
        ArrayList arrayList = new ArrayList();
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            LocalMedia localMedia2 = list.get(i2);
            if (localMedia2 != null && !TextUtils.isEmpty(localMedia2.getPath())) {
                CutInfo cutInfo = new CutInfo();
                cutInfo.setId(localMedia2.getId());
                cutInfo.setPath(localMedia2.getPath());
                cutInfo.setImageWidth(localMedia2.getWidth());
                cutInfo.setImageHeight(localMedia2.getHeight());
                cutInfo.setMimeType(localMedia2.getMimeType());
                cutInfo.setDuration(localMedia2.getDuration());
                cutInfo.setRealPath(localMedia2.getRealPath());
                arrayList.add(cutInfo);
            }
        }
        UCropManager.ofCrop(this, arrayList);
    }

    private void setLastCacheFolderData() {
        LocalMediaFolder folder = this.folderWindow.getFolder(ValueOf.toInt(this.mTvPictureTitle.getTag(C3979R.id.view_index_tag)));
        folder.setData(this.mAdapter.getData());
        folder.setCurrentDataPage(this.mPage);
        folder.setHasMore(this.isHasMore);
    }

    private void showDataNull(String str, int i2) {
        if (this.mTvEmpty.getVisibility() == 8 || this.mTvEmpty.getVisibility() == 4) {
            this.mTvEmpty.setCompoundDrawablesRelativeWithIntrinsicBounds(0, i2, 0, 0);
            this.mTvEmpty.setText(str);
            this.mTvEmpty.setVisibility(0);
        }
    }

    private void singleCropHandleResult(Intent intent) {
        Uri output;
        if (intent == null || (output = UCrop.getOutput(intent)) == null) {
            return;
        }
        ArrayList arrayList = new ArrayList();
        String path = output.getPath();
        if (this.mAdapter != null) {
            ArrayList parcelableArrayListExtra = intent.getParcelableArrayListExtra(PictureConfig.EXTRA_SELECT_LIST);
            if (parcelableArrayListExtra != null) {
                this.mAdapter.bindSelectData(parcelableArrayListExtra);
                this.mAdapter.notifyDataSetChanged();
            }
            List<LocalMedia> selectedData = this.mAdapter.getSelectedData();
            LocalMedia localMedia = null;
            LocalMedia localMedia2 = (selectedData == null || selectedData.size() <= 0) ? null : selectedData.get(0);
            if (localMedia2 != null) {
                this.config.originalPath = localMedia2.getPath();
                localMedia2.setCutPath(path);
                localMedia2.setChooseModel(this.config.chooseMode);
                boolean z = !TextUtils.isEmpty(path);
                if (SdkVersionUtils.checkedAndroid_Q() && PictureMimeType.isContent(localMedia2.getPath())) {
                    if (z) {
                        localMedia2.setSize(new File(path).length());
                    } else {
                        localMedia2.setSize(TextUtils.isEmpty(localMedia2.getRealPath()) ? 0L : new File(localMedia2.getRealPath()).length());
                    }
                    localMedia2.setAndroidQToPath(path);
                } else {
                    localMedia2.setSize(z ? new File(path).length() : 0L);
                }
                localMedia2.setCut(z);
                arrayList.add(localMedia2);
                handlerResult(arrayList);
                return;
            }
            if (parcelableArrayListExtra != null && parcelableArrayListExtra.size() > 0) {
                localMedia = (LocalMedia) parcelableArrayListExtra.get(0);
            }
            if (localMedia != null) {
                this.config.originalPath = localMedia.getPath();
                localMedia.setCutPath(path);
                localMedia.setChooseModel(this.config.chooseMode);
                boolean z2 = !TextUtils.isEmpty(path);
                if (SdkVersionUtils.checkedAndroid_Q() && PictureMimeType.isContent(localMedia.getPath())) {
                    if (z2) {
                        localMedia.setSize(new File(path).length());
                    } else {
                        localMedia.setSize(TextUtils.isEmpty(localMedia.getRealPath()) ? 0L : new File(localMedia.getRealPath()).length());
                    }
                    localMedia.setAndroidQToPath(path);
                } else {
                    localMedia.setSize(z2 ? new File(path).length() : 0L);
                }
                localMedia.setCut(z2);
                arrayList.add(localMedia);
                handlerResult(arrayList);
            }
        }
    }

    private void singleDirectReturnCameraHandleResult(String str) {
        boolean isHasImage = PictureMimeType.isHasImage(str);
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.enableCrop && isHasImage) {
            String str2 = pictureSelectionConfig.cameraPath;
            pictureSelectionConfig.originalPath = str2;
            UCropManager.ofCrop(this, str2, str);
        } else if (pictureSelectionConfig.isCompress && isHasImage) {
            compressImage(this.mAdapter.getSelectedData());
        } else {
            onResult(this.mAdapter.getSelectedData());
        }
    }

    private void singleRadioMediaImage() {
        List<LocalMedia> selectedData = this.mAdapter.getSelectedData();
        if (selectedData == null || selectedData.size() <= 0) {
            return;
        }
        int position = selectedData.get(0).getPosition();
        selectedData.clear();
        this.mAdapter.notifyItemChanged(position);
    }

    private void startCustomCamera() {
        if (!PermissionChecker.checkSelfPermission(this, "android.permission.RECORD_AUDIO")) {
            PermissionChecker.requestPermissions(this, new String[]{"android.permission.RECORD_AUDIO"}, 4);
        } else {
            startActivityForResult(new Intent(this, (Class<?>) PictureCustomCameraActivity.class), PictureConfig.REQUEST_CAMERA);
            overridePendingTransition(PictureSelectionConfig.windowAnimationStyle.activityEnterAnimation, C3979R.anim.picture_anim_fade_in);
        }
    }

    private void synchronousCover() {
        if (this.config.chooseMode == PictureMimeType.ofAll()) {
            PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<Boolean>() { // from class: com.luck.picture.lib.PictureSelectorActivity.2
                @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                public void onSuccess(Boolean bool) {
                }

                @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                public Boolean doInBackground() {
                    int size = PictureSelectorActivity.this.folderWindow.getFolderData().size();
                    for (int i2 = 0; i2 < size; i2++) {
                        LocalMediaFolder folder = PictureSelectorActivity.this.folderWindow.getFolder(i2);
                        if (folder != null) {
                            folder.setFirstImagePath(LocalMediaPageLoader.getInstance(PictureSelectorActivity.this.getContext()).getFirstCover(folder.getBucketId()));
                        }
                    }
                    return Boolean.TRUE;
                }
            });
        }
    }

    private void updateMediaFolder(List<LocalMediaFolder> list, LocalMedia localMedia) {
        File parentFile = new File(localMedia.getRealPath()).getParentFile();
        if (parentFile == null) {
            return;
        }
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            LocalMediaFolder localMediaFolder = list.get(i2);
            String name = localMediaFolder.getName();
            if (!TextUtils.isEmpty(name) && name.equals(parentFile.getName())) {
                localMediaFolder.setFirstImagePath(this.config.cameraPath);
                localMediaFolder.setImageNum(localMediaFolder.getImageNum() + 1);
                localMediaFolder.setCheckedNum(1);
                localMediaFolder.getData().add(0, localMedia);
                return;
            }
        }
    }

    /* renamed from: b */
    public /* synthetic */ void m4528b(List list, int i2, boolean z) {
        if (isFinishing()) {
            return;
        }
        dismissDialog();
        if (this.mAdapter != null) {
            this.isHasMore = true;
            if (z && list.size() == 0) {
                onRecyclerViewPreloadMore();
                return;
            }
            int size = this.mAdapter.getSize();
            int size2 = list.size();
            int i3 = this.oldCurrentListSize + size;
            this.oldCurrentListSize = i3;
            if (size2 >= size) {
                if (size <= 0 || size >= size2 || i3 == size2) {
                    this.mAdapter.bindData(list);
                } else if (isLocalMediaSame((LocalMedia) list.get(0))) {
                    this.mAdapter.bindData(list);
                } else {
                    this.mAdapter.getData().addAll(list);
                }
            }
            if (this.mAdapter.isDataEmpty()) {
                showDataNull(getString(C3979R.string.picture_empty), C3979R.drawable.picture_icon_no_data);
            } else {
                hideDataNull();
            }
        }
    }

    /* renamed from: c */
    public /* synthetic */ void m4529c(long j2, List list, int i2, boolean z) {
        if (isFinishing()) {
            return;
        }
        this.isHasMore = z;
        if (!z) {
            if (this.mAdapter.isDataEmpty()) {
                showDataNull(getString(j2 == -1 ? C3979R.string.picture_empty : C3979R.string.picture_data_null), C3979R.drawable.picture_icon_no_data);
                return;
            }
            return;
        }
        hideDataNull();
        int size = list.size();
        if (size > 0) {
            int size2 = this.mAdapter.getSize();
            this.mAdapter.getData().addAll(list);
            this.mAdapter.notifyItemRangeChanged(size2, this.mAdapter.getItemCount());
        } else {
            onRecyclerViewPreloadMore();
        }
        if (size < 10) {
            RecyclerPreloadView recyclerPreloadView = this.mRecyclerView;
            recyclerPreloadView.onScrolled(recyclerPreloadView.getScrollX(), this.mRecyclerView.getScrollY());
        }
    }

    public void changeImageNumber(List<LocalMedia> list) {
        if (!(list.size() != 0)) {
            this.mTvPictureOk.setEnabled(this.config.returnEmpty);
            this.mTvPictureOk.setSelected(false);
            this.mTvPicturePreview.setEnabled(false);
            this.mTvPicturePreview.setSelected(false);
            PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle == null) {
                PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
                if (pictureParameterStyle != null) {
                    int i2 = pictureParameterStyle.pictureUnCompleteTextColor;
                    if (i2 != 0) {
                        this.mTvPictureOk.setTextColor(i2);
                    }
                    int i3 = PictureSelectionConfig.style.pictureUnPreviewTextColor;
                    if (i3 != 0) {
                        this.mTvPicturePreview.setTextColor(i3);
                    }
                    if (TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnPreviewText)) {
                        this.mTvPicturePreview.setText(getString(C3979R.string.picture_preview));
                    } else {
                        this.mTvPicturePreview.setText(PictureSelectionConfig.style.pictureUnPreviewText);
                    }
                }
            } else if (TextUtils.isEmpty(pictureSelectorUIStyle.picture_bottom_previewDefaultText)) {
                this.mTvPicturePreview.setText(getString(C3979R.string.picture_preview));
            } else {
                this.mTvPicturePreview.setText(PictureSelectionConfig.uiStyle.picture_bottom_previewDefaultText);
            }
            if (this.numComplete) {
                initCompleteText(list.size());
                return;
            }
            this.mTvPictureImgNum.setVisibility(4);
            PictureSelectorUIStyle pictureSelectorUIStyle2 = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle2 != null) {
                if (TextUtils.isEmpty(pictureSelectorUIStyle2.picture_bottom_completeDefaultText)) {
                    return;
                }
                this.mTvPictureOk.setText(PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText);
                return;
            }
            PictureParameterStyle pictureParameterStyle2 = PictureSelectionConfig.style;
            if (pictureParameterStyle2 == null) {
                this.mTvPictureOk.setText(getString(C3979R.string.picture_please_select));
                return;
            } else {
                if (TextUtils.isEmpty(pictureParameterStyle2.pictureUnCompleteText)) {
                    return;
                }
                this.mTvPictureOk.setText(PictureSelectionConfig.style.pictureUnCompleteText);
                return;
            }
        }
        this.mTvPictureOk.setEnabled(true);
        this.mTvPictureOk.setSelected(true);
        this.mTvPicturePreview.setEnabled(true);
        this.mTvPicturePreview.setSelected(true);
        PictureSelectorUIStyle pictureSelectorUIStyle3 = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle3 == null) {
            PictureParameterStyle pictureParameterStyle3 = PictureSelectionConfig.style;
            if (pictureParameterStyle3 != null) {
                int i4 = pictureParameterStyle3.pictureCompleteTextColor;
                if (i4 != 0) {
                    this.mTvPictureOk.setTextColor(i4);
                }
                int i5 = PictureSelectionConfig.style.picturePreviewTextColor;
                if (i5 != 0) {
                    this.mTvPicturePreview.setTextColor(i5);
                }
                if (TextUtils.isEmpty(PictureSelectionConfig.style.picturePreviewText)) {
                    this.mTvPicturePreview.setText(getString(C3979R.string.picture_preview_num, new Object[]{Integer.valueOf(list.size())}));
                } else {
                    this.mTvPicturePreview.setText(PictureSelectionConfig.style.picturePreviewText);
                }
            }
        } else if (TextUtils.isEmpty(pictureSelectorUIStyle3.picture_bottom_previewNormalText)) {
            this.mTvPicturePreview.setText(getString(C3979R.string.picture_preview_num, new Object[]{Integer.valueOf(list.size())}));
        } else {
            PictureSelectorUIStyle pictureSelectorUIStyle4 = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle4.isCompleteReplaceNum) {
                this.mTvPicturePreview.setText(String.format(pictureSelectorUIStyle4.picture_bottom_previewNormalText, Integer.valueOf(list.size())));
            } else {
                this.mTvPicturePreview.setText(pictureSelectorUIStyle4.picture_bottom_previewNormalText);
            }
        }
        if (this.numComplete) {
            initCompleteText(list.size());
            return;
        }
        if (!this.isStartAnimation) {
            this.mTvPictureImgNum.startAnimation(this.animation);
        }
        this.mTvPictureImgNum.setVisibility(0);
        this.mTvPictureImgNum.setText(String.valueOf(list.size()));
        PictureSelectorUIStyle pictureSelectorUIStyle5 = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle5 == null) {
            PictureParameterStyle pictureParameterStyle4 = PictureSelectionConfig.style;
            if (pictureParameterStyle4 == null) {
                this.mTvPictureOk.setText(getString(C3979R.string.picture_completed));
            } else if (!TextUtils.isEmpty(pictureParameterStyle4.pictureCompleteText)) {
                this.mTvPictureOk.setText(PictureSelectionConfig.style.pictureCompleteText);
            }
        } else if (!TextUtils.isEmpty(pictureSelectorUIStyle5.picture_bottom_completeNormalText)) {
            this.mTvPictureOk.setText(PictureSelectionConfig.uiStyle.picture_bottom_completeNormalText);
        }
        this.isStartAnimation = false;
    }

    /* renamed from: d */
    public /* synthetic */ void m4530d(List list, int i2, boolean z) {
        if (isFinishing()) {
            return;
        }
        this.isHasMore = true;
        initPageModel(list);
        synchronousCover();
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public int getResourceId() {
        return C3979R.layout.picture_selector;
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void initCompleteText(int i2) {
        if (this.config.selectionMode == 1) {
            if (i2 <= 0) {
                PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
                if (pictureSelectorUIStyle != null) {
                    if (pictureSelectorUIStyle.isCompleteReplaceNum) {
                        this.mTvPictureOk.setText(!TextUtils.isEmpty(pictureSelectorUIStyle.picture_bottom_completeDefaultText) ? String.format(PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText, Integer.valueOf(i2), 1) : getString(C3979R.string.picture_please_select));
                        return;
                    } else {
                        this.mTvPictureOk.setText(!TextUtils.isEmpty(pictureSelectorUIStyle.picture_bottom_completeDefaultText) ? PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText : getString(C3979R.string.picture_please_select));
                        return;
                    }
                }
                PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
                if (pictureParameterStyle != null) {
                    if (!pictureParameterStyle.isCompleteReplaceNum || TextUtils.isEmpty(pictureParameterStyle.pictureUnCompleteText)) {
                        this.mTvPictureOk.setText(!TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnCompleteText) ? PictureSelectionConfig.style.pictureUnCompleteText : getString(C3979R.string.picture_done));
                        return;
                    } else {
                        this.mTvPictureOk.setText(String.format(PictureSelectionConfig.style.pictureUnCompleteText, Integer.valueOf(i2), 1));
                        return;
                    }
                }
                return;
            }
            PictureSelectorUIStyle pictureSelectorUIStyle2 = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle2 != null) {
                if (pictureSelectorUIStyle2.isCompleteReplaceNum) {
                    this.mTvPictureOk.setText(!TextUtils.isEmpty(pictureSelectorUIStyle2.picture_bottom_completeNormalText) ? String.format(PictureSelectionConfig.uiStyle.picture_bottom_completeNormalText, Integer.valueOf(i2), 1) : getString(C3979R.string.picture_done));
                    return;
                } else {
                    this.mTvPictureOk.setText(!TextUtils.isEmpty(pictureSelectorUIStyle2.picture_bottom_completeNormalText) ? PictureSelectionConfig.uiStyle.picture_bottom_completeNormalText : getString(C3979R.string.picture_done));
                    return;
                }
            }
            PictureParameterStyle pictureParameterStyle2 = PictureSelectionConfig.style;
            if (pictureParameterStyle2 != null) {
                if (!pictureParameterStyle2.isCompleteReplaceNum || TextUtils.isEmpty(pictureParameterStyle2.pictureCompleteText)) {
                    this.mTvPictureOk.setText(!TextUtils.isEmpty(PictureSelectionConfig.style.pictureCompleteText) ? PictureSelectionConfig.style.pictureCompleteText : getString(C3979R.string.picture_done));
                    return;
                } else {
                    this.mTvPictureOk.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(i2), 1));
                    return;
                }
            }
            return;
        }
        if (i2 <= 0) {
            PictureSelectorUIStyle pictureSelectorUIStyle3 = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle3 != null) {
                if (pictureSelectorUIStyle3.isCompleteReplaceNum) {
                    this.mTvPictureOk.setText(!TextUtils.isEmpty(pictureSelectorUIStyle3.picture_bottom_completeDefaultText) ? String.format(PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText, Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)) : getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}));
                    return;
                } else {
                    this.mTvPictureOk.setText(!TextUtils.isEmpty(pictureSelectorUIStyle3.picture_bottom_completeDefaultText) ? PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText : getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}));
                    return;
                }
            }
            PictureParameterStyle pictureParameterStyle3 = PictureSelectionConfig.style;
            if (pictureParameterStyle3 != null) {
                if (pictureParameterStyle3.isCompleteReplaceNum) {
                    this.mTvPictureOk.setText(!TextUtils.isEmpty(pictureParameterStyle3.pictureUnCompleteText) ? String.format(PictureSelectionConfig.style.pictureUnCompleteText, Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)) : getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}));
                    return;
                } else {
                    this.mTvPictureOk.setText(!TextUtils.isEmpty(pictureParameterStyle3.pictureUnCompleteText) ? PictureSelectionConfig.style.pictureUnCompleteText : getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}));
                    return;
                }
            }
            return;
        }
        PictureSelectorUIStyle pictureSelectorUIStyle4 = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle4 != null) {
            if (pictureSelectorUIStyle4.isCompleteReplaceNum) {
                if (TextUtils.isEmpty(pictureSelectorUIStyle4.picture_bottom_completeNormalText)) {
                    this.mTvPictureOk.setText(getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}));
                    return;
                } else {
                    this.mTvPictureOk.setText(String.format(PictureSelectionConfig.uiStyle.picture_bottom_completeNormalText, Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)));
                    return;
                }
            }
            if (TextUtils.isEmpty(pictureSelectorUIStyle4.picture_bottom_completeNormalText)) {
                this.mTvPictureOk.setText(getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}));
                return;
            } else {
                this.mTvPictureOk.setText(PictureSelectionConfig.uiStyle.picture_bottom_completeNormalText);
                return;
            }
        }
        PictureParameterStyle pictureParameterStyle4 = PictureSelectionConfig.style;
        if (pictureParameterStyle4 != null) {
            if (pictureParameterStyle4.isCompleteReplaceNum) {
                if (TextUtils.isEmpty(pictureParameterStyle4.pictureCompleteText)) {
                    this.mTvPictureOk.setText(getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}));
                    return;
                } else {
                    this.mTvPictureOk.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)));
                    return;
                }
            }
            if (TextUtils.isEmpty(pictureParameterStyle4.pictureCompleteText)) {
                this.mTvPictureOk.setText(getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}));
            } else {
                this.mTvPictureOk.setText(PictureSelectionConfig.style.pictureCompleteText);
            }
        }
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void initPictureSelectorStyle() {
        ColorStateList colorStateList;
        ColorStateList colorStateList2;
        ColorStateList colorStateList3;
        PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle != null) {
            int i2 = pictureSelectorUIStyle.picture_top_titleArrowDownDrawable;
            if (i2 != 0) {
                this.mIvArrow.setImageDrawable(ContextCompat.getDrawable(this, i2));
            }
            int i3 = PictureSelectionConfig.uiStyle.picture_top_titleTextColor;
            if (i3 != 0) {
                this.mTvPictureTitle.setTextColor(i3);
            }
            int i4 = PictureSelectionConfig.uiStyle.picture_top_titleTextSize;
            if (i4 != 0) {
                this.mTvPictureTitle.setTextSize(i4);
            }
            int[] iArr = PictureSelectionConfig.uiStyle.picture_top_titleRightTextColor;
            if (iArr.length > 0 && (colorStateList3 = AttrsUtils.getColorStateList(iArr)) != null) {
                this.mTvPictureRight.setTextColor(colorStateList3);
            }
            int i5 = PictureSelectionConfig.uiStyle.picture_top_titleRightTextSize;
            if (i5 != 0) {
                this.mTvPictureRight.setTextSize(i5);
            }
            int i6 = PictureSelectionConfig.uiStyle.picture_top_leftBack;
            if (i6 != 0) {
                this.mIvPictureLeftBack.setImageResource(i6);
            }
            int[] iArr2 = PictureSelectionConfig.uiStyle.picture_bottom_previewTextColor;
            if (iArr2.length > 0 && (colorStateList2 = AttrsUtils.getColorStateList(iArr2)) != null) {
                this.mTvPicturePreview.setTextColor(colorStateList2);
            }
            int i7 = PictureSelectionConfig.uiStyle.picture_bottom_previewTextSize;
            if (i7 != 0) {
                this.mTvPicturePreview.setTextSize(i7);
            }
            int i8 = PictureSelectionConfig.uiStyle.picture_bottom_completeRedDotBackground;
            if (i8 != 0) {
                this.mTvPictureImgNum.setBackgroundResource(i8);
            }
            int i9 = PictureSelectionConfig.uiStyle.picture_bottom_completeRedDotTextSize;
            if (i9 != 0) {
                this.mTvPictureImgNum.setTextSize(i9);
            }
            int i10 = PictureSelectionConfig.uiStyle.picture_bottom_completeRedDotTextColor;
            if (i10 != 0) {
                this.mTvPictureImgNum.setTextColor(i10);
            }
            int[] iArr3 = PictureSelectionConfig.uiStyle.picture_bottom_completeTextColor;
            if (iArr3.length > 0 && (colorStateList = AttrsUtils.getColorStateList(iArr3)) != null) {
                this.mTvPictureOk.setTextColor(colorStateList);
            }
            int i11 = PictureSelectionConfig.uiStyle.picture_bottom_completeTextSize;
            if (i11 != 0) {
                this.mTvPictureOk.setTextSize(i11);
            }
            int i12 = PictureSelectionConfig.uiStyle.picture_bottom_barBackgroundColor;
            if (i12 != 0) {
                this.mBottomLayout.setBackgroundColor(i12);
            }
            int i13 = PictureSelectionConfig.uiStyle.picture_container_backgroundColor;
            if (i13 != 0) {
                this.container.setBackgroundColor(i13);
            }
            if (!TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_top_titleRightDefaultText)) {
                this.mTvPictureRight.setText(PictureSelectionConfig.uiStyle.picture_top_titleRightDefaultText);
            }
            if (!TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText)) {
                this.mTvPictureOk.setText(PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText);
            }
            if (!TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_bottom_previewNormalText)) {
                this.mTvPicturePreview.setText(PictureSelectionConfig.uiStyle.picture_bottom_previewNormalText);
            }
            if (PictureSelectionConfig.uiStyle.picture_top_titleArrowLeftPadding != 0) {
                ((RelativeLayout.LayoutParams) this.mIvArrow.getLayoutParams()).leftMargin = PictureSelectionConfig.uiStyle.picture_top_titleArrowLeftPadding;
            }
            if (PictureSelectionConfig.uiStyle.picture_top_titleBarHeight > 0) {
                this.mTitleBar.getLayoutParams().height = PictureSelectionConfig.uiStyle.picture_top_titleBarHeight;
            }
            if (PictureSelectionConfig.uiStyle.picture_bottom_barHeight > 0) {
                this.mBottomLayout.getLayoutParams().height = PictureSelectionConfig.uiStyle.picture_bottom_barHeight;
            }
            if (this.config.isOriginalControl) {
                int i14 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureCheckStyle;
                if (i14 != 0) {
                    this.mCbOriginal.setButtonDrawable(i14);
                } else {
                    this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_checkbox));
                }
                int i15 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureTextColor;
                if (i15 != 0) {
                    this.mCbOriginal.setTextColor(i15);
                } else {
                    this.mCbOriginal.setTextColor(ContextCompat.getColor(this, C3979R.color.picture_color_white));
                }
                int i16 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureTextSize;
                if (i16 != 0) {
                    this.mCbOriginal.setTextSize(i16);
                }
                if (!TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_bottom_originalPictureText)) {
                    this.mCbOriginal.setText(PictureSelectionConfig.uiStyle.picture_bottom_originalPictureText);
                }
            } else {
                this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_checkbox));
                this.mCbOriginal.setTextColor(ContextCompat.getColor(this, C3979R.color.picture_color_white));
            }
        } else {
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle != null) {
                int i17 = pictureParameterStyle.pictureTitleDownResId;
                if (i17 != 0) {
                    this.mIvArrow.setImageDrawable(ContextCompat.getDrawable(this, i17));
                }
                int i18 = PictureSelectionConfig.style.pictureTitleTextColor;
                if (i18 != 0) {
                    this.mTvPictureTitle.setTextColor(i18);
                }
                int i19 = PictureSelectionConfig.style.pictureTitleTextSize;
                if (i19 != 0) {
                    this.mTvPictureTitle.setTextSize(i19);
                }
                PictureParameterStyle pictureParameterStyle2 = PictureSelectionConfig.style;
                int i20 = pictureParameterStyle2.pictureRightDefaultTextColor;
                if (i20 != 0) {
                    this.mTvPictureRight.setTextColor(i20);
                } else {
                    int i21 = pictureParameterStyle2.pictureCancelTextColor;
                    if (i21 != 0) {
                        this.mTvPictureRight.setTextColor(i21);
                    }
                }
                int i22 = PictureSelectionConfig.style.pictureRightTextSize;
                if (i22 != 0) {
                    this.mTvPictureRight.setTextSize(i22);
                }
                int i23 = PictureSelectionConfig.style.pictureLeftBackIcon;
                if (i23 != 0) {
                    this.mIvPictureLeftBack.setImageResource(i23);
                }
                int i24 = PictureSelectionConfig.style.pictureUnPreviewTextColor;
                if (i24 != 0) {
                    this.mTvPicturePreview.setTextColor(i24);
                }
                int i25 = PictureSelectionConfig.style.picturePreviewTextSize;
                if (i25 != 0) {
                    this.mTvPicturePreview.setTextSize(i25);
                }
                int i26 = PictureSelectionConfig.style.pictureCheckNumBgStyle;
                if (i26 != 0) {
                    this.mTvPictureImgNum.setBackgroundResource(i26);
                }
                int i27 = PictureSelectionConfig.style.pictureUnCompleteTextColor;
                if (i27 != 0) {
                    this.mTvPictureOk.setTextColor(i27);
                }
                int i28 = PictureSelectionConfig.style.pictureCompleteTextSize;
                if (i28 != 0) {
                    this.mTvPictureOk.setTextSize(i28);
                }
                int i29 = PictureSelectionConfig.style.pictureBottomBgColor;
                if (i29 != 0) {
                    this.mBottomLayout.setBackgroundColor(i29);
                }
                int i30 = PictureSelectionConfig.style.pictureContainerBackgroundColor;
                if (i30 != 0) {
                    this.container.setBackgroundColor(i30);
                }
                if (!TextUtils.isEmpty(PictureSelectionConfig.style.pictureRightDefaultText)) {
                    this.mTvPictureRight.setText(PictureSelectionConfig.style.pictureRightDefaultText);
                }
                if (!TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnCompleteText)) {
                    this.mTvPictureOk.setText(PictureSelectionConfig.style.pictureUnCompleteText);
                }
                if (!TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnPreviewText)) {
                    this.mTvPicturePreview.setText(PictureSelectionConfig.style.pictureUnPreviewText);
                }
                if (PictureSelectionConfig.style.pictureTitleRightArrowLeftPadding != 0) {
                    ((RelativeLayout.LayoutParams) this.mIvArrow.getLayoutParams()).leftMargin = PictureSelectionConfig.style.pictureTitleRightArrowLeftPadding;
                }
                if (PictureSelectionConfig.style.pictureTitleBarHeight > 0) {
                    this.mTitleBar.getLayoutParams().height = PictureSelectionConfig.style.pictureTitleBarHeight;
                }
                if (this.config.isOriginalControl) {
                    int i31 = PictureSelectionConfig.style.pictureOriginalControlStyle;
                    if (i31 != 0) {
                        this.mCbOriginal.setButtonDrawable(i31);
                    } else {
                        this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_checkbox));
                    }
                    int i32 = PictureSelectionConfig.style.pictureOriginalFontColor;
                    if (i32 != 0) {
                        this.mCbOriginal.setTextColor(i32);
                    } else {
                        this.mCbOriginal.setTextColor(ContextCompat.getColor(this, C3979R.color.picture_color_white));
                    }
                    int i33 = PictureSelectionConfig.style.pictureOriginalTextSize;
                    if (i33 != 0) {
                        this.mCbOriginal.setTextSize(i33);
                    }
                } else {
                    this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_checkbox));
                    this.mCbOriginal.setTextColor(ContextCompat.getColor(this, C3979R.color.picture_color_white));
                }
            } else {
                int typeValueColor = AttrsUtils.getTypeValueColor(getContext(), C3979R.attr.picture_title_textColor);
                if (typeValueColor != 0) {
                    this.mTvPictureTitle.setTextColor(typeValueColor);
                }
                int typeValueColor2 = AttrsUtils.getTypeValueColor(getContext(), C3979R.attr.picture_right_textColor);
                if (typeValueColor2 != 0) {
                    this.mTvPictureRight.setTextColor(typeValueColor2);
                }
                int typeValueColor3 = AttrsUtils.getTypeValueColor(getContext(), C3979R.attr.picture_container_backgroundColor);
                if (typeValueColor3 != 0) {
                    this.container.setBackgroundColor(typeValueColor3);
                }
                this.mIvPictureLeftBack.setImageDrawable(AttrsUtils.getTypeValueDrawable(getContext(), C3979R.attr.picture_leftBack_icon, C3979R.drawable.picture_icon_back));
                int i34 = this.config.downResId;
                if (i34 != 0) {
                    this.mIvArrow.setImageDrawable(ContextCompat.getDrawable(this, i34));
                } else {
                    this.mIvArrow.setImageDrawable(AttrsUtils.getTypeValueDrawable(getContext(), C3979R.attr.picture_arrow_down_icon, C3979R.drawable.picture_icon_arrow_down));
                }
                int typeValueColor4 = AttrsUtils.getTypeValueColor(getContext(), C3979R.attr.picture_bottom_bg);
                if (typeValueColor4 != 0) {
                    this.mBottomLayout.setBackgroundColor(typeValueColor4);
                }
                ColorStateList typeValueColorStateList = AttrsUtils.getTypeValueColorStateList(getContext(), C3979R.attr.picture_complete_textColor);
                if (typeValueColorStateList != null) {
                    this.mTvPictureOk.setTextColor(typeValueColorStateList);
                }
                ColorStateList typeValueColorStateList2 = AttrsUtils.getTypeValueColorStateList(getContext(), C3979R.attr.picture_preview_textColor);
                if (typeValueColorStateList2 != null) {
                    this.mTvPicturePreview.setTextColor(typeValueColorStateList2);
                }
                int typeValueSizeForInt = AttrsUtils.getTypeValueSizeForInt(getContext(), C3979R.attr.picture_titleRightArrow_LeftPadding);
                if (typeValueSizeForInt != 0) {
                    ((RelativeLayout.LayoutParams) this.mIvArrow.getLayoutParams()).leftMargin = typeValueSizeForInt;
                }
                this.mTvPictureImgNum.setBackground(AttrsUtils.getTypeValueDrawable(getContext(), C3979R.attr.picture_num_style, C3979R.drawable.picture_num_oval));
                int typeValueSizeForInt2 = AttrsUtils.getTypeValueSizeForInt(getContext(), C3979R.attr.picture_titleBar_height);
                if (typeValueSizeForInt2 > 0) {
                    this.mTitleBar.getLayoutParams().height = typeValueSizeForInt2;
                }
                if (this.config.isOriginalControl) {
                    this.mCbOriginal.setButtonDrawable(AttrsUtils.getTypeValueDrawable(getContext(), C3979R.attr.picture_original_check_style, C3979R.drawable.picture_original_wechat_checkbox));
                    int typeValueColor5 = AttrsUtils.getTypeValueColor(getContext(), C3979R.attr.picture_original_text_color);
                    if (typeValueColor5 != 0) {
                        this.mCbOriginal.setTextColor(typeValueColor5);
                    }
                }
            }
        }
        this.mTitleBar.setBackgroundColor(this.colorPrimary);
        this.mAdapter.bindSelectData(this.selectionMedias);
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void initWidgets() {
        super.initWidgets();
        this.container = findViewById(C3979R.id.container);
        this.mTitleBar = findViewById(C3979R.id.titleBar);
        this.mIvPictureLeftBack = (ImageView) findViewById(C3979R.id.pictureLeftBack);
        this.mTvPictureTitle = (TextView) findViewById(C3979R.id.picture_title);
        this.mTvPictureRight = (TextView) findViewById(C3979R.id.picture_right);
        this.mTvPictureOk = (TextView) findViewById(C3979R.id.picture_tv_ok);
        this.mCbOriginal = (CheckBox) findViewById(C3979R.id.cb_original);
        this.mIvArrow = (ImageView) findViewById(C3979R.id.ivArrow);
        this.viewClickMask = findViewById(C3979R.id.viewClickMask);
        this.mTvPicturePreview = (TextView) findViewById(C3979R.id.picture_id_preview);
        this.mTvPictureImgNum = (TextView) findViewById(C3979R.id.tv_media_num);
        this.mRecyclerView = (RecyclerPreloadView) findViewById(C3979R.id.picture_recycler);
        this.mBottomLayout = (RelativeLayout) findViewById(C3979R.id.select_bar_layout);
        this.mTvEmpty = (TextView) findViewById(C3979R.id.tv_empty);
        isNumComplete(this.numComplete);
        if (!this.numComplete) {
            this.animation = AnimationUtils.loadAnimation(this, C3979R.anim.picture_anim_modal_in);
        }
        this.mTvPicturePreview.setOnClickListener(this);
        if (this.config.isAutomaticTitleRecyclerTop) {
            this.mTitleBar.setOnClickListener(this);
        }
        this.mTvPicturePreview.setVisibility((this.config.chooseMode == PictureMimeType.ofAudio() || !this.config.enablePreview) ? 8 : 0);
        RelativeLayout relativeLayout = this.mBottomLayout;
        PictureSelectionConfig pictureSelectionConfig = this.config;
        relativeLayout.setVisibility((pictureSelectionConfig.selectionMode == 1 && pictureSelectionConfig.isSingleDirectReturn) ? 8 : 0);
        this.mIvPictureLeftBack.setOnClickListener(this);
        this.mTvPictureRight.setOnClickListener(this);
        this.mTvPictureOk.setOnClickListener(this);
        this.viewClickMask.setOnClickListener(this);
        this.mTvPictureImgNum.setOnClickListener(this);
        this.mTvPictureTitle.setOnClickListener(this);
        this.mIvArrow.setOnClickListener(this);
        this.mTvPictureTitle.setText(getString(this.config.chooseMode == PictureMimeType.ofAudio() ? C3979R.string.picture_all_audio : C3979R.string.picture_camera_roll));
        this.mTvPictureTitle.setTag(C3979R.id.view_tag, -1);
        FolderPopWindow folderPopWindow = new FolderPopWindow(this);
        this.folderWindow = folderPopWindow;
        folderPopWindow.setArrowImageView(this.mIvArrow);
        this.folderWindow.setOnAlbumItemClickListener(this);
        RecyclerPreloadView recyclerPreloadView = this.mRecyclerView;
        int i2 = this.config.imageSpanCount;
        if (i2 <= 0) {
            i2 = 4;
        }
        recyclerPreloadView.addItemDecoration(new GridSpacingItemDecoration(i2, ScreenUtils.dip2px(this, 2.0f), false));
        RecyclerPreloadView recyclerPreloadView2 = this.mRecyclerView;
        Context context = getContext();
        int i3 = this.config.imageSpanCount;
        recyclerPreloadView2.setLayoutManager(new GridLayoutManager(context, i3 > 0 ? i3 : 4));
        if (this.config.isPageStrategy) {
            this.mRecyclerView.setReachBottomRow(2);
            this.mRecyclerView.setOnRecyclerViewPreloadListener(this);
        } else {
            this.mRecyclerView.setHasFixedSize(true);
        }
        RecyclerView.ItemAnimator itemAnimator = this.mRecyclerView.getItemAnimator();
        if (itemAnimator != null) {
            ((SimpleItemAnimator) itemAnimator).setSupportsChangeAnimations(false);
            this.mRecyclerView.setItemAnimator(null);
        }
        loadAllMediaData();
        this.mTvEmpty.setText(this.config.chooseMode == PictureMimeType.ofAudio() ? getString(C3979R.string.picture_audio_empty) : getString(C3979R.string.picture_empty));
        StringUtils.tempTextFont(this.mTvEmpty, this.config.chooseMode);
        PictureImageGridAdapter pictureImageGridAdapter = new PictureImageGridAdapter(getContext(), this.config);
        this.mAdapter = pictureImageGridAdapter;
        pictureImageGridAdapter.setOnPhotoSelectChangedListener(this);
        int i4 = this.config.animationMode;
        if (i4 == 1) {
            this.mRecyclerView.setAdapter(new AlphaInAnimationAdapter(this.mAdapter));
        } else if (i4 != 2) {
            this.mRecyclerView.setAdapter(this.mAdapter);
        } else {
            this.mRecyclerView.setAdapter(new SlideInBottomAnimationAdapter(this.mAdapter));
        }
        if (this.config.isOriginalControl) {
            this.mCbOriginal.setVisibility(0);
            this.mCbOriginal.setChecked(this.config.isCheckOriginalImage);
            this.mCbOriginal.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: b.t.a.a.b0
                @Override // android.widget.CompoundButton.OnCheckedChangeListener
                public final void onCheckedChanged(CompoundButton compoundButton, boolean z) {
                    PictureSelectorActivity.this.config.isCheckOriginalImage = z;
                }
            });
        }
    }

    public void multiCropHandleResult(Intent intent) {
        List<CutInfo> multipleOutput;
        if (intent == null || (multipleOutput = UCrop.getMultipleOutput(intent)) == null || multipleOutput.size() == 0) {
            return;
        }
        int size = multipleOutput.size();
        boolean checkedAndroid_Q = SdkVersionUtils.checkedAndroid_Q();
        ArrayList parcelableArrayListExtra = intent.getParcelableArrayListExtra(PictureConfig.EXTRA_SELECT_LIST);
        if (parcelableArrayListExtra != null) {
            this.mAdapter.bindSelectData(parcelableArrayListExtra);
            this.mAdapter.notifyDataSetChanged();
        }
        PictureImageGridAdapter pictureImageGridAdapter = this.mAdapter;
        int i2 = 0;
        if ((pictureImageGridAdapter != null ? pictureImageGridAdapter.getSelectedData().size() : 0) == size) {
            List<LocalMedia> selectedData = this.mAdapter.getSelectedData();
            while (i2 < size) {
                CutInfo cutInfo = multipleOutput.get(i2);
                LocalMedia localMedia = selectedData.get(i2);
                localMedia.setCut(!TextUtils.isEmpty(cutInfo.getCutPath()));
                localMedia.setPath(cutInfo.getPath());
                localMedia.setMimeType(cutInfo.getMimeType());
                localMedia.setCutPath(cutInfo.getCutPath());
                localMedia.setWidth(cutInfo.getImageWidth());
                localMedia.setHeight(cutInfo.getImageHeight());
                localMedia.setAndroidQToPath(checkedAndroid_Q ? cutInfo.getCutPath() : localMedia.getAndroidQToPath());
                localMedia.setSize(!TextUtils.isEmpty(cutInfo.getCutPath()) ? new File(cutInfo.getCutPath()).length() : localMedia.getSize());
                i2++;
            }
            handlerResult(selectedData);
            return;
        }
        ArrayList arrayList = new ArrayList();
        while (i2 < size) {
            CutInfo cutInfo2 = multipleOutput.get(i2);
            LocalMedia localMedia2 = new LocalMedia();
            localMedia2.setId(cutInfo2.getId());
            localMedia2.setCut(!TextUtils.isEmpty(cutInfo2.getCutPath()));
            localMedia2.setPath(cutInfo2.getPath());
            localMedia2.setCutPath(cutInfo2.getCutPath());
            localMedia2.setMimeType(cutInfo2.getMimeType());
            localMedia2.setWidth(cutInfo2.getImageWidth());
            localMedia2.setHeight(cutInfo2.getImageHeight());
            localMedia2.setDuration(cutInfo2.getDuration());
            localMedia2.setChooseModel(this.config.chooseMode);
            localMedia2.setAndroidQToPath(checkedAndroid_Q ? cutInfo2.getCutPath() : cutInfo2.getAndroidQToPath());
            if (!TextUtils.isEmpty(cutInfo2.getCutPath())) {
                localMedia2.setSize(new File(cutInfo2.getCutPath()).length());
            } else if (SdkVersionUtils.checkedAndroid_Q() && PictureMimeType.isContent(cutInfo2.getPath())) {
                localMedia2.setSize(!TextUtils.isEmpty(cutInfo2.getRealPath()) ? new File(cutInfo2.getRealPath()).length() : 0L);
            } else {
                localMedia2.setSize(new File(cutInfo2.getPath()).length());
            }
            arrayList.add(localMedia2);
            i2++;
        }
        handlerResult(arrayList);
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onActivityResult(int i2, int i3, Intent intent) {
        Throwable th;
        ArrayList parcelableArrayListExtra;
        super.onActivityResult(i2, i3, intent);
        if (i3 != -1) {
            if (i3 == 0) {
                previewCallback(intent);
                return;
            } else {
                if (i3 != 96 || intent == null || (th = (Throwable) intent.getSerializableExtra(UCrop.EXTRA_ERROR)) == null) {
                    return;
                }
                ToastUtils.m4555s(getContext(), th.getMessage());
                return;
            }
        }
        if (i2 == 69) {
            singleCropHandleResult(intent);
            return;
        }
        if (i2 == 166) {
            if (intent == null || (parcelableArrayListExtra = intent.getParcelableArrayListExtra(PictureConfig.EXTRA_SELECT_LIST)) == null || parcelableArrayListExtra.size() <= 0) {
                return;
            }
            onResult(parcelableArrayListExtra);
            return;
        }
        if (i2 == 609) {
            multiCropHandleResult(intent);
        } else {
            if (i2 != 909) {
                return;
            }
            dispatchHandleCamera(intent);
        }
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        super.onBackPressed();
        OnResultCallbackListener onResultCallbackListener = PictureSelectionConfig.listener;
        if (onResultCallbackListener != null) {
            onResultCallbackListener.onCancel();
        }
        exit();
    }

    @Override // com.luck.picture.lib.listener.OnPhotoSelectChangedListener
    public void onChange(List<LocalMedia> list) {
        changeImageNumber(list);
    }

    public void onChangeData(List<LocalMedia> list) {
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        int id = view.getId();
        if (id == C3979R.id.pictureLeftBack || id == C3979R.id.picture_right) {
            FolderPopWindow folderPopWindow = this.folderWindow;
            if (folderPopWindow == null || !folderPopWindow.isShowing()) {
                onBackPressed();
                return;
            } else {
                this.folderWindow.dismiss();
                return;
            }
        }
        if (id == C3979R.id.picture_title || id == C3979R.id.ivArrow || id == C3979R.id.viewClickMask) {
            if (this.folderWindow.isShowing()) {
                this.folderWindow.dismiss();
                return;
            }
            if (this.folderWindow.isEmpty()) {
                return;
            }
            this.folderWindow.showAsDropDown(this.mTitleBar);
            if (this.config.isSingleDirectReturn) {
                return;
            }
            this.folderWindow.updateFolderCheckStatus(this.mAdapter.getSelectedData());
            return;
        }
        if (id == C3979R.id.picture_id_preview) {
            onPreview();
            return;
        }
        if (id == C3979R.id.picture_tv_ok || id == C3979R.id.tv_media_num) {
            onComplete();
            return;
        }
        if (id == C3979R.id.titleBar && this.config.isAutomaticTitleRecyclerTop) {
            if (SystemClock.uptimeMillis() - this.intervalClickTime >= CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION) {
                this.intervalClickTime = SystemClock.uptimeMillis();
            } else if (this.mAdapter.getItemCount() > 0) {
                this.mRecyclerView.scrollToPosition(0);
            }
        }
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (bundle != null) {
            this.allFolderSize = bundle.getInt(PictureConfig.EXTRA_ALL_FOLDER_SIZE);
            this.oldCurrentListSize = bundle.getInt(PictureConfig.EXTRA_OLD_CURRENT_LIST_SIZE, 0);
            List<LocalMedia> obtainSelectorList = PictureSelector.obtainSelectorList(bundle);
            if (obtainSelectorList == null) {
                obtainSelectorList = this.selectionMedias;
            }
            this.selectionMedias = obtainSelectorList;
            PictureImageGridAdapter pictureImageGridAdapter = this.mAdapter;
            if (pictureImageGridAdapter != null) {
                this.isStartAnimation = true;
                pictureImageGridAdapter.bindSelectData(obtainSelectorList);
            }
        }
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        Handler handler;
        super.onDestroy();
        Animation animation = this.animation;
        if (animation != null) {
            animation.cancel();
            this.animation = null;
        }
        if (this.mediaPlayer == null || (handler = this.mHandler) == null) {
            return;
        }
        handler.removeCallbacks(this.mRunnable);
        this.mediaPlayer.release();
        this.mediaPlayer = null;
    }

    @Override // com.luck.picture.lib.listener.OnAlbumItemClickListener
    public void onItemClick(int i2, boolean z, long j2, String str, List<LocalMedia> list) {
        this.mAdapter.setShowCamera(this.config.isCamera && z);
        this.mTvPictureTitle.setText(str);
        TextView textView = this.mTvPictureTitle;
        int i3 = C3979R.id.view_tag;
        long j3 = ValueOf.toLong(textView.getTag(i3));
        this.mTvPictureTitle.setTag(C3979R.id.view_count_tag, Integer.valueOf(this.folderWindow.getFolder(i2) != null ? this.folderWindow.getFolder(i2).getImageNum() : 0));
        if (!this.config.isPageStrategy) {
            this.mAdapter.bindData(list);
            this.mRecyclerView.smoothScrollToPosition(0);
        } else if (j3 != j2) {
            setLastCacheFolderData();
            if (!isCurrentCacheFolderData(i2)) {
                this.mPage = 1;
                showPleaseDialog();
                LocalMediaPageLoader.getInstance(getContext()).loadPageMediaData(j2, this.mPage, new OnQueryDataResultListener() { // from class: b.t.a.a.x
                    @Override // com.luck.picture.lib.listener.OnQueryDataResultListener
                    public final void onComplete(List list2, int i4, boolean z2) {
                        PictureSelectorActivity pictureSelectorActivity = PictureSelectorActivity.this;
                        pictureSelectorActivity.isHasMore = z2;
                        if (pictureSelectorActivity.isFinishing()) {
                            return;
                        }
                        if (list2.size() == 0) {
                            pictureSelectorActivity.mAdapter.clear();
                        }
                        pictureSelectorActivity.mAdapter.bindData(list2);
                        pictureSelectorActivity.mRecyclerView.onScrolled(0, 0);
                        pictureSelectorActivity.mRecyclerView.smoothScrollToPosition(0);
                        pictureSelectorActivity.dismissDialog();
                    }
                });
            }
        }
        this.mTvPictureTitle.setTag(i3, Long.valueOf(j2));
        this.folderWindow.dismiss();
    }

    @Override // com.luck.picture.lib.listener.OnRecyclerViewPreloadMoreListener
    public void onRecyclerViewPreloadMore() {
        loadMoreData();
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onRequestPermissionsResult(int i2, @NonNull String[] strArr, @NonNull int[] iArr) {
        super.onRequestPermissionsResult(i2, strArr, iArr);
        if (i2 == 1) {
            if (iArr.length <= 0 || iArr[0] != 0) {
                showPermissionsDialog(false, getString(C3979R.string.picture_jurisdiction));
                return;
            } else {
                readLocalMedia();
                return;
            }
        }
        if (i2 == 2) {
            if (iArr.length <= 0 || iArr[0] != 0) {
                showPermissionsDialog(true, getString(C3979R.string.picture_camera));
                return;
            } else {
                onTakePhoto();
                return;
            }
        }
        if (i2 == 4) {
            if (iArr.length <= 0 || iArr[0] != 0) {
                showPermissionsDialog(false, getString(C3979R.string.picture_audio));
                return;
            } else {
                startCustomCamera();
                return;
            }
        }
        if (i2 != 5) {
            return;
        }
        if (iArr.length <= 0 || iArr[0] != 0) {
            showPermissionsDialog(false, getString(C3979R.string.picture_jurisdiction));
        } else {
            startCamera();
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        CheckBox checkBox;
        super.onResume();
        if (this.isEnterSetting) {
            if (!PermissionChecker.checkSelfPermission(this, "android.permission.READ_EXTERNAL_STORAGE") || !PermissionChecker.checkSelfPermission(this, "android.permission.WRITE_EXTERNAL_STORAGE")) {
                showPermissionsDialog(false, getString(C3979R.string.picture_jurisdiction));
            } else if (this.mAdapter.isDataEmpty()) {
                readLocalMedia();
            }
            this.isEnterSetting = false;
        }
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (!pictureSelectionConfig.isOriginalControl || (checkBox = this.mCbOriginal) == null) {
            return;
        }
        checkBox.setChecked(pictureSelectionConfig.isCheckOriginalImage);
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onSaveInstanceState(@NotNull Bundle bundle) {
        super.onSaveInstanceState(bundle);
        PictureImageGridAdapter pictureImageGridAdapter = this.mAdapter;
        if (pictureImageGridAdapter != null) {
            bundle.putInt(PictureConfig.EXTRA_OLD_CURRENT_LIST_SIZE, pictureImageGridAdapter.getSize());
            if (this.folderWindow.getFolderData().size() > 0) {
                bundle.putInt(PictureConfig.EXTRA_ALL_FOLDER_SIZE, this.folderWindow.getFolder(0).getImageNum());
            }
            if (this.mAdapter.getSelectedData() != null) {
                PictureSelector.saveSelectorList(bundle, this.mAdapter.getSelectedData());
            }
        }
    }

    @Override // com.luck.picture.lib.listener.OnPhotoSelectChangedListener
    public void onTakePhoto() {
        if (!PermissionChecker.checkSelfPermission(this, "android.permission.CAMERA")) {
            PermissionChecker.requestPermissions(this, new String[]{"android.permission.CAMERA"}, 2);
        } else if (PermissionChecker.checkSelfPermission(this, "android.permission.READ_EXTERNAL_STORAGE") && PermissionChecker.checkSelfPermission(this, "android.permission.WRITE_EXTERNAL_STORAGE")) {
            startCamera();
        } else {
            PermissionChecker.requestPermissions(this, new String[]{"android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"}, 5);
        }
    }

    public void playOrPause() {
        try {
            MediaPlayer mediaPlayer = this.mediaPlayer;
            if (mediaPlayer != null) {
                if (mediaPlayer.isPlaying()) {
                    this.mediaPlayer.pause();
                } else {
                    this.mediaPlayer.start();
                }
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public void readLocalMedia() {
        showPleaseDialog();
        if (this.config.isPageStrategy) {
            LocalMediaPageLoader.getInstance(getContext()).loadAllMedia(new OnQueryDataResultListener() { // from class: b.t.a.a.y
                @Override // com.luck.picture.lib.listener.OnQueryDataResultListener
                public final void onComplete(List list, int i2, boolean z) {
                    PictureSelectorActivity.this.m4530d(list, i2, z);
                }
            });
        } else {
            PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<List<LocalMediaFolder>>() { // from class: com.luck.picture.lib.PictureSelectorActivity.1
                @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                public List<LocalMediaFolder> doInBackground() {
                    return new LocalMediaLoader(PictureSelectorActivity.this.getContext()).loadAllMedia();
                }

                @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                public void onSuccess(List<LocalMediaFolder> list) {
                    PictureSelectorActivity.this.initStandardModel(list);
                }
            });
        }
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void showPermissionsDialog(final boolean z, String str) {
        if (isFinishing()) {
            return;
        }
        final PictureCustomDialog pictureCustomDialog = new PictureCustomDialog(getContext(), C3979R.layout.picture_wind_base_dialog);
        pictureCustomDialog.setCancelable(false);
        pictureCustomDialog.setCanceledOnTouchOutside(false);
        Button button = (Button) pictureCustomDialog.findViewById(C3979R.id.btn_cancel);
        Button button2 = (Button) pictureCustomDialog.findViewById(C3979R.id.btn_commit);
        button2.setText(getString(C3979R.string.picture_go_setting));
        TextView textView = (TextView) pictureCustomDialog.findViewById(C3979R.id.tvTitle);
        TextView textView2 = (TextView) pictureCustomDialog.findViewById(C3979R.id.tv_content);
        textView.setText(getString(C3979R.string.picture_prompt));
        textView2.setText(str);
        button.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.z
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PictureSelectorActivity pictureSelectorActivity = PictureSelectorActivity.this;
                PictureCustomDialog pictureCustomDialog2 = pictureCustomDialog;
                boolean z2 = z;
                if (!pictureSelectorActivity.isFinishing()) {
                    pictureCustomDialog2.dismiss();
                }
                if (z2) {
                    return;
                }
                OnResultCallbackListener onResultCallbackListener = PictureSelectionConfig.listener;
                if (onResultCallbackListener != null) {
                    onResultCallbackListener.onCancel();
                }
                pictureSelectorActivity.exit();
            }
        });
        button2.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.u
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PictureSelectorActivity pictureSelectorActivity = PictureSelectorActivity.this;
                PictureCustomDialog pictureCustomDialog2 = pictureCustomDialog;
                if (!pictureSelectorActivity.isFinishing()) {
                    pictureCustomDialog2.dismiss();
                }
                PermissionChecker.launchAppDetailsSettings(pictureSelectorActivity.getContext());
                pictureSelectorActivity.isEnterSetting = true;
            }
        });
        pictureCustomDialog.show();
    }

    public void startCamera() {
        if (DoubleUtils.isFastDoubleClick()) {
            return;
        }
        OnCustomCameraInterfaceListener onCustomCameraInterfaceListener = PictureSelectionConfig.onCustomCameraInterfaceListener;
        if (onCustomCameraInterfaceListener != null) {
            if (this.config.chooseMode == 0) {
                PhotoItemSelectedDialog newInstance = PhotoItemSelectedDialog.newInstance();
                newInstance.setOnItemClickListener(this);
                newInstance.show(getSupportFragmentManager(), "PhotoItemSelectedDialog");
                return;
            } else {
                Context context = getContext();
                PictureSelectionConfig pictureSelectionConfig = this.config;
                onCustomCameraInterfaceListener.onCameraClick(context, pictureSelectionConfig, pictureSelectionConfig.chooseMode);
                PictureSelectionConfig pictureSelectionConfig2 = this.config;
                pictureSelectionConfig2.cameraMimeType = pictureSelectionConfig2.chooseMode;
                return;
            }
        }
        PictureSelectionConfig pictureSelectionConfig3 = this.config;
        if (pictureSelectionConfig3.isUseCustomCamera) {
            startCustomCamera();
            return;
        }
        int i2 = pictureSelectionConfig3.chooseMode;
        if (i2 == 0) {
            PhotoItemSelectedDialog newInstance2 = PhotoItemSelectedDialog.newInstance();
            newInstance2.setOnItemClickListener(this);
            newInstance2.show(getSupportFragmentManager(), "PhotoItemSelectedDialog");
        } else if (i2 == 1) {
            startOpenCamera();
        } else if (i2 == 2) {
            startOpenCameraVideo();
        } else {
            if (i2 != 3) {
                return;
            }
            startOpenCameraAudio();
        }
    }

    public void startPreview(List<LocalMedia> list, int i2) {
        LocalMedia localMedia = list.get(i2);
        String mimeType = localMedia.getMimeType();
        Bundle bundle = new Bundle();
        ArrayList arrayList = new ArrayList();
        if (PictureMimeType.isHasVideo(mimeType)) {
            PictureSelectionConfig pictureSelectionConfig = this.config;
            if (pictureSelectionConfig.selectionMode == 1 && !pictureSelectionConfig.enPreviewVideo) {
                arrayList.add(localMedia);
                onResult(arrayList);
                return;
            }
            OnVideoSelectedPlayCallback onVideoSelectedPlayCallback = PictureSelectionConfig.customVideoPlayCallback;
            if (onVideoSelectedPlayCallback != null) {
                onVideoSelectedPlayCallback.startPlayVideo(localMedia);
                return;
            } else {
                bundle.putParcelable(PictureConfig.EXTRA_MEDIA_KEY, localMedia);
                JumpUtils.startPictureVideoPlayActivity(getContext(), bundle, 166);
                return;
            }
        }
        if (PictureMimeType.isHasAudio(mimeType)) {
            if (this.config.selectionMode != 1) {
                AudioDialog(localMedia.getPath());
                return;
            } else {
                arrayList.add(localMedia);
                onResult(arrayList);
                return;
            }
        }
        OnCustomImagePreviewCallback onCustomImagePreviewCallback = PictureSelectionConfig.onCustomImagePreviewCallback;
        if (onCustomImagePreviewCallback != null) {
            onCustomImagePreviewCallback.onCustomPreviewCallback(getContext(), list, i2);
            return;
        }
        List<LocalMedia> selectedData = this.mAdapter.getSelectedData();
        ImagesObservable.getInstance().savePreviewMediaData(new ArrayList(list));
        bundle.putParcelableArrayList(PictureConfig.EXTRA_SELECT_LIST, (ArrayList) selectedData);
        bundle.putInt("position", i2);
        bundle.putBoolean(PictureConfig.EXTRA_CHANGE_ORIGINAL, this.config.isCheckOriginalImage);
        bundle.putBoolean(PictureConfig.EXTRA_SHOW_CAMERA, this.mAdapter.isShowCamera());
        bundle.putLong(PictureConfig.EXTRA_BUCKET_ID, ValueOf.toLong(this.mTvPictureTitle.getTag(C3979R.id.view_tag)));
        bundle.putInt("page", this.mPage);
        bundle.putParcelable(PictureConfig.EXTRA_CONFIG, this.config);
        bundle.putInt(PictureConfig.EXTRA_DATA_COUNT, ValueOf.toInt(this.mTvPictureTitle.getTag(C3979R.id.view_count_tag)));
        bundle.putString(PictureConfig.EXTRA_IS_CURRENT_DIRECTORY, this.mTvPictureTitle.getText().toString());
        Context context = getContext();
        PictureSelectionConfig pictureSelectionConfig2 = this.config;
        JumpUtils.startPicturePreviewActivity(context, pictureSelectionConfig2.isWeChatStyle, bundle, pictureSelectionConfig2.selectionMode == 1 ? 69 : UCrop.REQUEST_MULTI_CROP);
        overridePendingTransition(PictureSelectionConfig.windowAnimationStyle.activityPreviewEnterAnimation, C3979R.anim.picture_anim_fade_in);
    }

    public void stop(String str) {
        MediaPlayer mediaPlayer = this.mediaPlayer;
        if (mediaPlayer != null) {
            try {
                mediaPlayer.stop();
                this.mediaPlayer.reset();
                this.mediaPlayer.setDataSource(str);
                this.mediaPlayer.prepare();
                this.mediaPlayer.seekTo(0);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    @Override // com.luck.picture.lib.listener.OnPhotoSelectChangedListener
    public void onPictureClick(LocalMedia localMedia, int i2) {
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.selectionMode != 1 || !pictureSelectionConfig.isSingleDirectReturn) {
            startPreview(this.mAdapter.getData(), i2);
            return;
        }
        ArrayList arrayList = new ArrayList();
        arrayList.add(localMedia);
        if (!this.config.enableCrop || !PictureMimeType.isHasImage(localMedia.getMimeType()) || this.config.isCheckOriginalImage) {
            handlerResult(arrayList);
        } else {
            this.mAdapter.bindSelectData(arrayList);
            UCropManager.ofCrop(this, localMedia.getPath(), localMedia.getMimeType());
        }
    }

    @Override // com.luck.picture.lib.listener.OnItemClickListener
    public void onItemClick(View view, int i2) {
        if (i2 == 0) {
            OnCustomCameraInterfaceListener onCustomCameraInterfaceListener = PictureSelectionConfig.onCustomCameraInterfaceListener;
            if (onCustomCameraInterfaceListener != null) {
                onCustomCameraInterfaceListener.onCameraClick(getContext(), this.config, 1);
                this.config.cameraMimeType = PictureMimeType.ofImage();
                return;
            }
            startOpenCamera();
            return;
        }
        if (i2 != 1) {
            return;
        }
        OnCustomCameraInterfaceListener onCustomCameraInterfaceListener2 = PictureSelectionConfig.onCustomCameraInterfaceListener;
        if (onCustomCameraInterfaceListener2 != null) {
            onCustomCameraInterfaceListener2.onCameraClick(getContext(), this.config, 1);
            this.config.cameraMimeType = PictureMimeType.ofVideo();
            return;
        }
        startOpenCameraVideo();
    }
}
