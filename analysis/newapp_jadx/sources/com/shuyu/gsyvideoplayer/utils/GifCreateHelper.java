package com.shuyu.gsyvideoplayer.utils;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.media.ThumbnailUtils;
import com.shuyu.gsyvideoplayer.video.StandardGSYVideoPlayer;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p362y.p363a.p366f.InterfaceC2926b;
import p005b.p362y.p363a.p366f.InterfaceC2929e;

/* loaded from: classes2.dex */
public class GifCreateHelper {
    private int mDelay;
    private int mFrequencyCount;
    private InterfaceC2926b mGSYVideoGifSaveListener;
    private List<String> mPicList;
    private StandardGSYVideoPlayer mPlayer;
    private int mSampleSize;
    private boolean mSaveShotBitmapSuccess;
    private int mScaleSize;
    private Timer mTimer;
    private TaskLocal mTimerTask;
    private File mTmpPath;

    public class TaskLocal extends TimerTask {
        private TaskLocal() {
        }

        @Override // java.util.TimerTask, java.lang.Runnable
        public void run() {
            if (GifCreateHelper.this.mSaveShotBitmapSuccess) {
                GifCreateHelper.this.mSaveShotBitmapSuccess = false;
                GifCreateHelper.this.startSaveBitmap();
            }
        }
    }

    public GifCreateHelper(StandardGSYVideoPlayer standardGSYVideoPlayer, InterfaceC2926b interfaceC2926b) {
        this(standardGSYVideoPlayer, interfaceC2926b, 0, 1, 5, 50);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startSaveBitmap() {
        File file = this.mTmpPath;
        StringBuilder m586H = C1499a.m586H("GSY-TMP-FRAME");
        m586H.append(System.currentTimeMillis());
        m586H.append(".tmp");
        this.mPlayer.saveFrame(new File(file, m586H.toString()), new InterfaceC2929e() { // from class: com.shuyu.gsyvideoplayer.utils.GifCreateHelper.2
            @Override // p005b.p362y.p363a.p366f.InterfaceC2929e
            public void result(boolean z, File file2) {
                GifCreateHelper.this.mSaveShotBitmapSuccess = true;
                if (z) {
                    StringBuilder m586H2 = C1499a.m586H(" SUCCESS CREATE FILE ");
                    m586H2.append(file2.getAbsolutePath());
                    Debuger.printfError(m586H2.toString());
                    GifCreateHelper.this.mPicList.add(file2.getAbsolutePath());
                }
            }
        });
    }

    public void cancelTask() {
        TaskLocal taskLocal = this.mTimerTask;
        if (taskLocal != null) {
            taskLocal.cancel();
            this.mTimerTask = null;
        }
    }

    public void createGif(File file, List<String> list, int i2, int i3, int i4, InterfaceC2926b interfaceC2926b) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        AnimatedGifEncoder animatedGifEncoder = new AnimatedGifEncoder();
        animatedGifEncoder.start(byteArrayOutputStream);
        animatedGifEncoder.setRepeat(0);
        animatedGifEncoder.setDelay(i2);
        int i5 = 0;
        while (i5 < list.size()) {
            BitmapFactory.Options options = new BitmapFactory.Options();
            options.inSampleSize = i3;
            options.inJustDecodeBounds = true;
            BitmapFactory.decodeFile(list.get(i5), options);
            double d2 = i4;
            double d3 = options.outWidth / d2;
            double d4 = options.outHeight / d2;
            options.inJustDecodeBounds = false;
            Bitmap decodeFile = BitmapFactory.decodeFile(list.get(i5), options);
            Bitmap extractThumbnail = ThumbnailUtils.extractThumbnail(decodeFile, (int) d3, (int) d4);
            animatedGifEncoder.addFrame(extractThumbnail);
            decodeFile.recycle();
            extractThumbnail.recycle();
            i5++;
            interfaceC2926b.m3401a(i5, list.size());
        }
        animatedGifEncoder.finish();
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(file.getPath());
            byteArrayOutputStream.writeTo(fileOutputStream);
            byteArrayOutputStream.flush();
            fileOutputStream.flush();
            byteArrayOutputStream.close();
            fileOutputStream.close();
            interfaceC2926b.result(true, file);
        } catch (IOException e2) {
            e2.printStackTrace();
            interfaceC2926b.result(false, file);
        }
    }

    public void startGif(File file) {
        this.mTmpPath = file;
        cancelTask();
        this.mPicList.clear();
        TaskLocal taskLocal = new TaskLocal();
        this.mTimerTask = taskLocal;
        this.mTimer.schedule(taskLocal, 0L, this.mFrequencyCount);
    }

    public void stopGif(final File file) {
        cancelTask();
        this.mSaveShotBitmapSuccess = true;
        new Thread(new Runnable() { // from class: com.shuyu.gsyvideoplayer.utils.GifCreateHelper.1
            @Override // java.lang.Runnable
            public void run() {
                if (GifCreateHelper.this.mPicList.size() <= 2) {
                    GifCreateHelper.this.mGSYVideoGifSaveListener.result(false, null);
                } else {
                    GifCreateHelper gifCreateHelper = GifCreateHelper.this;
                    gifCreateHelper.createGif(file, gifCreateHelper.mPicList, GifCreateHelper.this.mDelay, GifCreateHelper.this.mSampleSize, GifCreateHelper.this.mScaleSize, GifCreateHelper.this.mGSYVideoGifSaveListener);
                }
            }
        }).start();
    }

    public GifCreateHelper(StandardGSYVideoPlayer standardGSYVideoPlayer, InterfaceC2926b interfaceC2926b, int i2, int i3, int i4, int i5) {
        this.mSaveShotBitmapSuccess = true;
        this.mTimer = new Timer();
        this.mPicList = new ArrayList();
        this.mDelay = 0;
        this.mSampleSize = 1;
        this.mScaleSize = 5;
        this.mFrequencyCount = 50;
        this.mPlayer = standardGSYVideoPlayer;
        this.mGSYVideoGifSaveListener = interfaceC2926b;
        this.mDelay = i2;
        this.mSampleSize = i3;
        this.mScaleSize = i4;
        this.mFrequencyCount = i5;
    }
}
