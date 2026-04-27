package com.ding.rtc;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteboardSurfaceView extends SurfaceView implements SurfaceHolder.Callback {
    private final List<Callback> mCallbacks;
    private boolean mIsReady;
    private boolean mIsTransparent;
    private boolean mPassThrough;
    private View.OnTouchListener mRtcTouchListener;
    private View.OnTouchListener mUserTouchListener;

    public interface Callback {
        void onViewDestroyed(View v);

        void onViewReady(View v, int w, int h);

        void onViewSizeChanged(View v, int w, int h);
    }

    public RtcWhiteboardSurfaceView(Context context) {
        super(context);
        this.mIsReady = false;
        this.mPassThrough = false;
        this.mIsTransparent = false;
        this.mCallbacks = new ArrayList();
        getHolder().addCallback(this);
    }

    public RtcWhiteboardSurfaceView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mIsReady = false;
        this.mPassThrough = false;
        this.mIsTransparent = false;
        this.mCallbacks = new ArrayList();
        getHolder().addCallback(this);
    }

    public boolean isViewReady() {
        return this.mIsReady;
    }

    public void addCallback(Callback cb) {
        if (cb != null && !this.mCallbacks.contains(cb)) {
            this.mCallbacks.add(cb);
        }
    }

    public void removeCallback(Callback cb) {
        if (cb != null) {
            this.mCallbacks.remove(cb);
        }
    }

    public void removeCallbacks() {
        this.mCallbacks.clear();
    }

    public void setPassThrough(boolean passThrough) {
        this.mPassThrough = passThrough;
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceChanged(SurfaceHolder holder, int format, int w, int h) {
        if (!this.mIsReady) {
            this.mIsReady = true;
            for (Callback cb : this.mCallbacks) {
                cb.onViewReady(this, w, h);
            }
            return;
        }
        for (Callback cb2 : this.mCallbacks) {
            cb2.onViewSizeChanged(this, w, h);
        }
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceCreated(SurfaceHolder holder) {
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceDestroyed(SurfaceHolder holder) {
        this.mIsReady = false;
        for (Callback cb : this.mCallbacks) {
            cb.onViewDestroyed(this);
        }
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        if (this.mPassThrough) {
            return false;
        }
        boolean handled = false;
        View.OnTouchListener onTouchListener = this.mUserTouchListener;
        if (onTouchListener != null && onTouchListener.onTouch(this, event)) {
            handled = true;
        }
        super.onTouchEvent(event);
        View.OnTouchListener onTouchListener2 = this.mRtcTouchListener;
        if (onTouchListener2 != null && onTouchListener2.onTouch(this, event)) {
            return true;
        }
        return handled;
    }

    @Override // android.view.View
    public void setOnTouchListener(View.OnTouchListener listener) {
        this.mUserTouchListener = listener;
    }

    public void setRtcTouchListener(View.OnTouchListener listener) {
        this.mRtcTouchListener = listener;
    }

    public void setTransparent(boolean enable) {
        if (enable) {
            setZOrderOnTop(true);
            getHolder().setFormat(-2);
        } else {
            setZOrderMediaOverlay(false);
        }
        this.mIsTransparent = enable;
    }

    public boolean isTransparent() {
        return this.mIsTransparent;
    }
}
