package com.ding.rtc;

import android.view.MotionEvent;
import android.view.Surface;
import android.view.View;
import com.ding.rtc.RtcWhiteboardDrawer;
import com.ding.rtc.RtcWhiteboardSurfaceView;
import com.ding.rtc.api.DingRtcWhiteBoardTypes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteboardBaseImpl implements RtcWhiteboardBase {
    private static final String TAG = RtcWhiteboardImpl.class.getSimpleName();
    private long mNativePtr;
    protected int mType;
    protected DingRtcWhiteboardView mView;
    protected final RtcWhiteboardDrawer mWbDrawer;
    protected RtcWhiteboardSurfaceView mWbView;
    protected RtcWhiteboardSurfaceView.Callback mWbViewCallback;
    protected final Object mWhiteBoardLock = new Object();
    protected boolean mEnableLaserTrail = true;
    protected boolean mEnableEraseTrail = false;
    protected boolean mEnableDrawer = true;
    protected DingRtcWhiteBoardTypes.DingRtcWBToolType mToolType = DingRtcWhiteBoardTypes.DingRtcWBToolType.NONE;

    native int nativeAddPage(long instance, int type, boolean autoSwitch);

    native int nativeAddStamp(long instance, String stampId, String stampPath, boolean resizable);

    native int nativeBroadcastMessage(long instance, int type, String msg, int size);

    native int nativeClose(long instance, int type);

    native int nativeCopyDocPage(long instance, int type, String srcDocId, int srcPageNum, String dstDocId, int dstPageNum, boolean clearDstPage);

    native String nativeCreateDoc(long instance, int type, String name, int width, int height, int totalPages, boolean autoSwitch);

    native String nativeCreateDoc(long instance, int type, String docName, int docType, String[] docUrls, String transDocId, boolean autoSwitch);

    native int nativeDeleteDoc(long instance, int type, String docId);

    native String nativeGetCurrentDocID(long instance, int type);

    native int nativeGetCurrentPageNumber(long instance, int type);

    native DingRtcWhiteboardDocInfo nativeGetDocInfo(long instance, int type, String docId);

    native String[] nativeGetDocList(long instance, int type);

    native float nativeGetMaxZoomScale(long instance, int type);

    native float nativeGetMinZoomScale(long instance, int type);

    native boolean nativeGetRedoStatus(long instance, int type);

    native int nativeGetToolType(long instance, int type);

    native int nativeGetTotalNumberOfPages(long instance, int type);

    native boolean nativeGetUndoStatus(long instance, int type);

    native float nativeGetZoomScale(long instance, int type);

    native int nativeGotoPage(long instance, int type, int pageNo);

    native int nativeInsertPage(long instance, int type, int pageNo, boolean autoSwitch);

    native int nativeJoin(long instance, int type);

    native int nativeLeave(long instance, int type);

    native int nativeNextPage(long instance, int type);

    native int nativeOpen(long instance, int type, View view);

    native int nativePrevPage(long instance, int type);

    native int nativeRedo(long instance, int type);

    native int nativeRemovePage(long instance, int type, int pageNo, boolean switchNext);

    native int nativeSaveDocToImages(long instance, int type, String docId, String outputDir);

    native int nativeSendUserMessage(long instance, int type, String userId, String msg, int size);

    native int nativeSetColor(long instance, int type, float r, float g, float b, float a);

    native int nativeSetFillColor(long instance, int type, float r, float g, float b, float a);

    native int nativeSetFillType(long instance, int type, int fillType);

    native int nativeSetFontSize(long instance, int type, int size);

    native int nativeSetFontStyle(long instance, int type, int fontStyle);

    native int nativeSetLineWidth(long instance, int type, int size);

    native int nativeSetMaxZoomScale(long instance, int type, float scale);

    native int nativeSetMinZoomScale(long instance, int type, float scale);

    native int nativeSetRole(long instance, int type, int role);

    native int nativeSetScalingMode(long instance, int type, int mode);

    native int nativeSetStamp(long instance, String stampId);

    native int nativeSetToolType(long instance, int type, int toolType);

    native int nativeSetZoomScale(long instance, int type, float scale);

    native int nativeSetZoomScaleWithTranslate(long instance, int type, float scale, float tx, float ty);

    native int nativeStop(long instance, int type);

    native int nativeSurfaceDestroyed(long instance, int type);

    native int nativeSurfaceReady(long instance, int type, Surface view);

    native int nativeSwitchDoc(long instance, int type, String docId);

    native int nativeUndo(long instance, int type);

    native int nativeUpdateViewSize(long instance, int type, int w, int h);

    public RtcWhiteboardBaseImpl(int type, long nativePtr) {
        this.mType = 0;
        this.mType = type;
        this.mNativePtr = nativePtr;
        this.mWbDrawer = new RtcWhiteboardDrawer(nativePtr, 0, new AnonymousClass1());
    }

    /* JADX INFO: renamed from: com.ding.rtc.RtcWhiteboardBaseImpl$1, reason: invalid class name */
    class AnonymousClass1 implements RtcWhiteboardDrawer.Callback {
        AnonymousClass1() {
        }

        @Override // com.ding.rtc.RtcWhiteboardDrawer.Callback
        public void onGestureHandlerAdd(final RtcWhiteboardGestureHandler gesHandler) {
            if (RtcWhiteboardBaseImpl.this.mWbView != null) {
                RtcWhiteboardBaseImpl.this.mWbView.setRtcTouchListener(new View.OnTouchListener() { // from class: com.ding.rtc.-$$Lambda$RtcWhiteboardBaseImpl$1$aYSz-YkCm0q0YM4KO_9wbctnwfY
                    @Override // android.view.View.OnTouchListener
                    public final boolean onTouch(View view, MotionEvent motionEvent) {
                        return gesHandler.handleEvent(motionEvent).booleanValue();
                    }
                });
            }
        }

        @Override // com.ding.rtc.RtcWhiteboardDrawer.Callback
        public void onGestureHandlerRemove() {
            if (RtcWhiteboardBaseImpl.this.mWbView != null) {
                RtcWhiteboardBaseImpl.this.mWbView.setRtcTouchListener(null);
            }
        }

        @Override // com.ding.rtc.RtcWhiteboardDrawer.Callback
        public void onActionBegin() {
        }

        @Override // com.ding.rtc.RtcWhiteboardDrawer.Callback
        public void onActionMove(float x, float y) {
            if (RtcWhiteboardBaseImpl.this.mView != null) {
                RtcWhiteboardLableView labelView = RtcWhiteboardBaseImpl.this.mView.getAttachLabelView();
                if (RtcWhiteboardBaseImpl.this.mToolType == DingRtcWhiteBoardTypes.DingRtcWBToolType.LASER) {
                    labelView.updateLaserPoint(x, y);
                } else if (RtcWhiteboardBaseImpl.this.mToolType == DingRtcWhiteBoardTypes.DingRtcWBToolType.DELETER) {
                    labelView.updateErasePoint(x, y);
                }
            }
        }

        @Override // com.ding.rtc.RtcWhiteboardDrawer.Callback
        public void onActionEnd() {
            if (RtcWhiteboardBaseImpl.this.mView != null) {
                RtcWhiteboardLableView labelView = RtcWhiteboardBaseImpl.this.mView.getAttachLabelView();
                if (RtcWhiteboardBaseImpl.this.mToolType == DingRtcWhiteBoardTypes.DingRtcWBToolType.DELETER) {
                    labelView.clearEraseTrail();
                }
            }
        }
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int join() {
        Logging.i(TAG, "join.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeJoin(j, this.mType);
        }
        return -1;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int leave() {
        Logging.i(TAG, "leave.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeLeave(j, this.mType);
        }
        return -1;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int stop() {
        Logging.i(TAG, "stop.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeStop(j, this.mType);
        }
        return -1;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setRole(DingRtcWhiteBoardTypes.DingRtcWBRoleType role) {
        Logging.i(TAG, "setRole.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetRole(j, this.mType, role.getValue());
        }
        return -1;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int open(DingRtcWhiteboardView window) {
        RtcWhiteboardLableView labelView;
        Logging.i(TAG, "open window");
        if (window == null) {
            return -1;
        }
        if (this.mView == window) {
            Logging.i(TAG, "open same window, skip");
            return 0;
        }
        this.mView = window;
        if (window != null && (labelView = window.getAttachLabelView()) != null) {
            labelView.enableLaser(this.mToolType == DingRtcWhiteBoardTypes.DingRtcWBToolType.LASER);
            if (this.mToolType == DingRtcWhiteBoardTypes.DingRtcWBToolType.LASER) {
                labelView.enableLaserTrail(this.mEnableLaserTrail);
            } else {
                labelView.enableLaserTrail(false);
            }
            if (this.mToolType == DingRtcWhiteBoardTypes.DingRtcWBToolType.DELETER) {
                labelView.enableEraseTrail(this.mEnableEraseTrail);
            } else {
                labelView.enableEraseTrail(false);
            }
        }
        synchronized (this.mWhiteBoardLock) {
            if (this.mNativePtr == 0) {
                return -1;
            }
            nativeOpen(this.mNativePtr, this.mType, window);
            if (this.mView != null) {
                this.mView.setNativeHandle(this.mNativePtr);
            }
            final RtcWhiteboardSurfaceView wbView = window.getAttachRtcWbView();
            Logging.i(TAG, "open surfaceview:" + wbView);
            this.mWbView = wbView;
            RtcWhiteboardSurfaceView.Callback callback = new RtcWhiteboardSurfaceView.Callback() { // from class: com.ding.rtc.RtcWhiteboardBaseImpl.2
                @Override // com.ding.rtc.RtcWhiteboardSurfaceView.Callback
                public void onViewReady(View v, int w, int h) {
                    Logging.i(RtcWhiteboardBaseImpl.TAG, "onViewReady w:" + w + ", h:" + h + ", view " + v);
                    synchronized (RtcWhiteboardBaseImpl.this.mWhiteBoardLock) {
                        if (RtcWhiteboardBaseImpl.this.mNativePtr == 0) {
                            return;
                        }
                        RtcWhiteboardBaseImpl.this.nativeSurfaceReady(RtcWhiteboardBaseImpl.this.mNativePtr, RtcWhiteboardBaseImpl.this.mType, wbView.getHolder().getSurface());
                    }
                }

                @Override // com.ding.rtc.RtcWhiteboardSurfaceView.Callback
                public void onViewSizeChanged(View v, int w, int h) {
                    Logging.i(RtcWhiteboardBaseImpl.TAG, "onViewSizeChanged w:" + w + ", h:" + h + ", view " + v);
                    synchronized (RtcWhiteboardBaseImpl.this.mWhiteBoardLock) {
                        if (RtcWhiteboardBaseImpl.this.mNativePtr == 0) {
                            return;
                        }
                        RtcWhiteboardBaseImpl.this.nativeUpdateViewSize(RtcWhiteboardBaseImpl.this.mNativePtr, RtcWhiteboardBaseImpl.this.mType, w, h);
                    }
                }

                @Override // com.ding.rtc.RtcWhiteboardSurfaceView.Callback
                public void onViewDestroyed(View v) {
                    Logging.i(RtcWhiteboardBaseImpl.TAG, "onViewDestroyed view " + v);
                    synchronized (RtcWhiteboardBaseImpl.this.mWhiteBoardLock) {
                        if (RtcWhiteboardBaseImpl.this.mNativePtr == 0) {
                            return;
                        }
                        RtcWhiteboardBaseImpl.this.nativeSurfaceDestroyed(RtcWhiteboardBaseImpl.this.mNativePtr, RtcWhiteboardBaseImpl.this.mType);
                    }
                }
            };
            this.mWbViewCallback = callback;
            wbView.addCallback(callback);
            if (this.mEnableDrawer) {
                this.mWbDrawer.start(this.mWbView.getContext().getApplicationContext(), wbView);
            }
            if (!wbView.isViewReady()) {
                return 0;
            }
            synchronized (this.mWhiteBoardLock) {
                if (this.mNativePtr == 0) {
                    return -1;
                }
                Logging.i(TAG, "open view is ready");
                nativeSurfaceReady(this.mNativePtr, this.mType, wbView.getHolder().getSurface());
                return 0;
            }
        }
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int close() {
        Logging.i(TAG, "close.");
        try {
            throw new RuntimeException("call close");
        } catch (Exception e) {
            e.printStackTrace();
            DingRtcWhiteboardView dingRtcWhiteboardView = this.mView;
            if (dingRtcWhiteboardView != null) {
                dingRtcWhiteboardView.close();
                this.mView = null;
            }
            RtcWhiteboardSurfaceView rtcWhiteboardSurfaceView = this.mWbView;
            if (rtcWhiteboardSurfaceView != null) {
                rtcWhiteboardSurfaceView.removeCallback(this.mWbViewCallback);
                this.mWbViewCallback = null;
                this.mWbView = null;
            }
            long j = this.mNativePtr;
            if (j != 0) {
                return nativeClose(j, this.mType);
            }
            return 0;
        }
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setToolType(DingRtcWhiteBoardTypes.DingRtcWBToolType toolType) {
        RtcWhiteboardLableView labelView;
        Logging.i(TAG, "setToolType.");
        DingRtcWhiteboardView dingRtcWhiteboardView = this.mView;
        if (dingRtcWhiteboardView != null && (labelView = dingRtcWhiteboardView.getAttachLabelView()) != null) {
            labelView.enableLaser(toolType == DingRtcWhiteBoardTypes.DingRtcWBToolType.LASER);
            if (toolType == DingRtcWhiteBoardTypes.DingRtcWBToolType.LASER) {
                labelView.enableLaserTrail(this.mEnableLaserTrail);
            } else {
                labelView.enableLaserTrail(false);
            }
            if (toolType == DingRtcWhiteBoardTypes.DingRtcWBToolType.DELETER) {
                labelView.enableEraseTrail(this.mEnableEraseTrail);
            } else {
                labelView.enableEraseTrail(false);
            }
        }
        long j = this.mNativePtr;
        if (j == 0) {
            return 0;
        }
        this.mToolType = toolType;
        return nativeSetToolType(j, this.mType, toolType.getValue());
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setLineWidth(int size) {
        Logging.i(TAG, "setLineWidth.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetLineWidth(j, this.mType, size);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setColor(DingRtcWhiteBoardTypes.DingRtcWBColor color) {
        Logging.i(TAG, "setColor.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetColor(j, this.mType, color.r, color.g, color.b, color.a);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setFillColor(DingRtcWhiteBoardTypes.DingRtcWBColor color) {
        Logging.i(TAG, "setFillColor.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetFillColor(j, this.mType, color.r, color.g, color.b, color.a);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setFillType(DingRtcWhiteBoardTypes.DingRtcWBFillType fillType) {
        Logging.i(TAG, "setFillType.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetFillType(j, this.mType, fillType.getValue());
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setFontStyle(DingRtcWhiteBoardTypes.DingRtcWBFontStyle style) {
        Logging.i(TAG, "setFontStyle.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetFontStyle(j, this.mType, style.getValue());
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setFontSize(int size) {
        Logging.i(TAG, "setFontSize.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetFontSize(j, this.mType, size);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int undo() {
        Logging.i(TAG, "undo.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeUndo(j, this.mType);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int redo() {
        Logging.i(TAG, "redo.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeRedo(j, this.mType);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public DingRtcWhiteBoardTypes.DingRtcWBToolType getToolType() {
        Logging.i(TAG, "getToolType.");
        long j = this.mNativePtr;
        if (j != 0) {
            return DingRtcWhiteBoardTypes.DingRtcWBToolType.fromValue(nativeGetToolType(j, this.mType));
        }
        return null;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public boolean getUndoStatus() {
        Logging.i(TAG, "getUndoStatus.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeGetUndoStatus(j, this.mType);
        }
        return false;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public boolean getRedoStatus() {
        Logging.i(TAG, "getRedoStatus.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeGetRedoStatus(j, this.mType);
        }
        return false;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int addStamp(DingRtcWhiteBoardTypes.DingRtcWBStamp stamp) {
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeAddStamp(j, stamp.stampId, stamp.stampPath, stamp.resizable);
        }
        Logging.i(TAG, "addStamp.");
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setStamp(String stampId) {
        Logging.i(TAG, "setStamp.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetStamp(j, stampId);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setZoomScale(float scale) {
        Logging.i(TAG, "setZoomScale.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetZoomScale(j, this.mType, scale);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setZoomScaleWithTranslate(float scale, float tx, float ty) {
        Logging.i(TAG, "setZoomScaleWithTranslate.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetZoomScaleWithTranslate(j, this.mType, scale, tx, ty);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setMinZoomScale(float scale) {
        Logging.i(TAG, "setMinZoomScale.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetMinZoomScale(j, this.mType, scale);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setMaxZoomScale(float scale) {
        Logging.i(TAG, "setMaxZoomScale.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSetMaxZoomScale(j, this.mType, scale);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public float getZoomScale() {
        Logging.i(TAG, "getZoomScale.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeGetZoomScale(j, this.mType);
        }
        return 0.0f;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public float getMinZoomScale() {
        Logging.i(TAG, "getMinZoomScale.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeGetMinZoomScale(j, this.mType);
        }
        return 0.0f;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public float getMaxZoomScale() {
        Logging.i(TAG, "getMaxZoomScale.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeGetMaxZoomScale(j, this.mType);
        }
        return 0.0f;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int setScalingMode(DingRtcWhiteBoardTypes.DingRtcWBScalingMode mode) {
        Logging.i(TAG, "setScalingMode.");
        synchronized (this.mWhiteBoardLock) {
            if (this.mNativePtr != 0) {
                return nativeSetScalingMode(this.mNativePtr, this.mType, mode.getValue());
            }
            return -1;
        }
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int getCurrentPageNumber() {
        Logging.i(TAG, "getCurrentPageNumber.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeGetCurrentPageNumber(j, this.mType);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int getTotalNumberOfPages() {
        Logging.i(TAG, "getTotalNumberOfPages.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeGetTotalNumberOfPages(j, this.mType);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int addPage(boolean autoSwitch) {
        Logging.i(TAG, "addPage.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeAddPage(j, this.mType, autoSwitch);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int insertPage(int pageNo, boolean autoSwitch) {
        Logging.i(TAG, "insertPage.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeInsertPage(j, this.mType, pageNo, autoSwitch);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int removePage(int pageNo, boolean switchNext) {
        Logging.i(TAG, "removePage.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeRemovePage(j, this.mType, pageNo, switchNext);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int gotoPage(int pageNo) {
        Logging.i(TAG, "gotoPage.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeGotoPage(j, this.mType, pageNo);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int nextPage() {
        Logging.i(TAG, "nextPage.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeNextPage(j, this.mType);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int prevPage() {
        Logging.i(TAG, "prevPage.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativePrevPage(j, this.mType);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public String getCurrentDocID() {
        Logging.i(TAG, "getCurrentDocID.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeGetCurrentDocID(j, this.mType);
        }
        return "";
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public DingRtcWhiteboardDocInfo getDocInfo(String docId) {
        Logging.i(TAG, "getDocInfo.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeGetDocInfo(j, this.mType, docId);
        }
        return null;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public List<String> getDocList() {
        String[] docIdArray;
        Logging.i(TAG, "getDocList.");
        long j = this.mNativePtr;
        if (j != 0 && (docIdArray = nativeGetDocList(j, this.mType)) != null) {
            List<String> docIdList = new ArrayList<>();
            for (String docId : docIdArray) {
                docIdList.add(docId);
            }
            return docIdList;
        }
        return Collections.emptyList();
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public String createDoc(DingRtcWhiteBoardTypes.DingRtcWBDocExtContents contents, boolean autoSwitch) {
        Logging.i(TAG, "createDoc.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeCreateDoc(j, this.mType, contents.name, contents.width, contents.height, contents.totalPages, autoSwitch);
        }
        return "";
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public String createDoc(DingRtcWhiteBoardTypes.DingRtcWBDocContents contents, boolean autoSwitch) {
        Logging.i(TAG, "createDoc.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeCreateDoc(j, this.mType, contents.name, contents.type.getValue(), (String[]) contents.urls.toArray(new String[contents.urls.size()]), contents.transDocId, autoSwitch);
        }
        return "";
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int deleteDoc(String docId) {
        Logging.i(TAG, "deleteDoc.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeDeleteDoc(j, this.mType, docId);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int switchDoc(String docId) {
        Logging.i(TAG, "switchDoc.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSwitchDoc(j, this.mType, docId);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int copyDocPage(String srcDocId, int srcPageNum, String dstDocId, int dstPageNum, boolean clearDstPage) {
        Logging.i(TAG, "copyDocPage.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeCopyDocPage(j, this.mType, srcDocId, srcPageNum, dstDocId, dstPageNum, clearDstPage);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int saveDocToImages(String docId, String outputDir) {
        Logging.i(TAG, "saveDocToImages.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSaveDocToImages(j, this.mType, docId, outputDir);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int sendUserMessage(String userId, String msg, int size) {
        Logging.i(TAG, "sendUserMessage.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeSendUserMessage(j, this.mType, userId, msg, size);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBase
    public int broadcastMessage(String msg, int size) {
        Logging.i(TAG, "broadcastMessage.");
        long j = this.mNativePtr;
        if (j != 0) {
            return nativeBroadcastMessage(j, this.mType, msg, size);
        }
        return 0;
    }

    public void destroy() {
        Logging.i(TAG, "base destroy.");
        this.mNativePtr = 0L;
    }

    public void setOpaque(final boolean opaque) {
        Logging.i(TAG, "setOpaque " + opaque);
        DingRtcWhiteboardView dingRtcWhiteboardView = this.mView;
        if (dingRtcWhiteboardView != null) {
            dingRtcWhiteboardView.post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$RtcWhiteboardBaseImpl$Y4ropoCuqdQKsBGOZ_p_Go1oiHs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$setOpaque$0$RtcWhiteboardBaseImpl(opaque);
                }
            });
        }
    }

    public /* synthetic */ void lambda$setOpaque$0$RtcWhiteboardBaseImpl(final boolean opaque) {
        RtcWhiteboardSurfaceView rtcWhiteboardSurfaceView = this.mWbView;
        if (rtcWhiteboardSurfaceView != null) {
            rtcWhiteboardSurfaceView.setVisibility(8);
            this.mWbView.setTransparent(!opaque);
            this.mWbView.setVisibility(0);
        }
    }

    public boolean getOpaque() {
        Logging.i(TAG, "getOpaque.");
        RtcWhiteboardSurfaceView rtcWhiteboardSurfaceView = this.mWbView;
        if (rtcWhiteboardSurfaceView == null) {
            return false;
        }
        boolean transparent = rtcWhiteboardSurfaceView.isTransparent();
        return !transparent;
    }

    public void setLimitSize(int w, int h) {
        Logging.i(TAG, "setLimitSize.");
        DingRtcWhiteboardView dingRtcWhiteboardView = this.mView;
        if (dingRtcWhiteboardView != null) {
            dingRtcWhiteboardView.setLimitSize(w, h);
        }
    }

    public void addCursor(String labelId, String name) {
        Logging.i(TAG, "addCursor.");
        DingRtcWhiteboardView dingRtcWhiteboardView = this.mView;
        if (dingRtcWhiteboardView != null) {
            dingRtcWhiteboardView.addCursor(labelId, name);
        }
    }

    public void removeCursor(String labelId) {
        Logging.i(TAG, "removeCursor.");
        DingRtcWhiteboardView dingRtcWhiteboardView = this.mView;
        if (dingRtcWhiteboardView != null) {
            dingRtcWhiteboardView.removeCursor(labelId);
        }
    }

    public void updateCursor(String labelId, float x, float y, int color, int type, String name) {
        Logging.i(TAG, "updateCursor.");
        DingRtcWhiteboardView dingRtcWhiteboardView = this.mView;
        if (dingRtcWhiteboardView != null) {
            dingRtcWhiteboardView.updateCursor(labelId, x, y, color, type, name);
        }
    }

    public DingRtcWhiteboardView getView() {
        return this.mView;
    }

    boolean checkNativeInvalid() {
        if (this.mNativePtr == 0) {
            Logging.w(TAG, "native ptr null");
            return true;
        }
        return false;
    }

    protected long getNativePtr() {
        return this.mNativePtr;
    }
}
