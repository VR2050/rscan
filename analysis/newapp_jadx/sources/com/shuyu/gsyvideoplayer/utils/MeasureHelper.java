package com.shuyu.gsyvideoplayer.utils;

import android.view.View;
import java.lang.ref.WeakReference;

/* loaded from: classes2.dex */
public final class MeasureHelper {
    private int mCurrentAspectRatio = 0;
    private int mMeasuredHeight;
    private int mMeasuredWidth;
    private final MeasureFormVideoParamsListener mParamsListener;
    private int mVideoHeight;
    private int mVideoRotationDegree;
    private int mVideoSarDen;
    private int mVideoSarNum;
    private int mVideoWidth;
    private WeakReference<View> mWeakView;

    public interface MeasureFormVideoParamsListener {
        int getCurrentVideoHeight();

        int getCurrentVideoWidth();

        int getVideoSarDen();

        int getVideoSarNum();
    }

    public MeasureHelper(View view, MeasureFormVideoParamsListener measureFormVideoParamsListener) {
        this.mParamsListener = measureFormVideoParamsListener;
        this.mWeakView = new WeakReference<>(view);
    }

    /* JADX WARN: Code restructure failed: missing block: B:45:0x00f2, code lost:
    
        if (r4 != false) goto L78;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x00f7, code lost:
    
        r15 = (int) (r2 / r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x00fb, code lost:
    
        r14 = (int) (r5 * r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x00f5, code lost:
    
        if (r4 != false) goto L77;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void doMeasure(int r14, int r15) {
        /*
            Method dump skipped, instructions count: 346
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.shuyu.gsyvideoplayer.utils.MeasureHelper.doMeasure(int, int):void");
    }

    public int getMeasuredHeight() {
        return this.mMeasuredHeight;
    }

    public int getMeasuredWidth() {
        return this.mMeasuredWidth;
    }

    public View getView() {
        WeakReference<View> weakReference = this.mWeakView;
        if (weakReference == null) {
            return null;
        }
        return weakReference.get();
    }

    public void prepareMeasure(int i2, int i3, int i4) {
        MeasureFormVideoParamsListener measureFormVideoParamsListener = this.mParamsListener;
        if (measureFormVideoParamsListener != null) {
            try {
                int currentVideoWidth = measureFormVideoParamsListener.getCurrentVideoWidth();
                int currentVideoHeight = this.mParamsListener.getCurrentVideoHeight();
                Debuger.printfLog("videoWidth: " + currentVideoWidth + " videoHeight: " + currentVideoHeight);
                int videoSarNum = this.mParamsListener.getVideoSarNum();
                int videoSarDen = this.mParamsListener.getVideoSarDen();
                if (currentVideoWidth > 0 && currentVideoHeight > 0) {
                    setVideoSampleAspectRatio(videoSarNum, videoSarDen);
                    setVideoSize(currentVideoWidth, currentVideoHeight);
                }
                setVideoRotation(i4);
                doMeasure(i2, i3);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    public void setAspectRatio(int i2) {
        this.mCurrentAspectRatio = i2;
    }

    public void setVideoRotation(int i2) {
        this.mVideoRotationDegree = i2;
    }

    public void setVideoSampleAspectRatio(int i2, int i3) {
        this.mVideoSarNum = i2;
        this.mVideoSarDen = i3;
    }

    public void setVideoSize(int i2, int i3) {
        this.mVideoWidth = i2;
        this.mVideoHeight = i3;
    }
}
