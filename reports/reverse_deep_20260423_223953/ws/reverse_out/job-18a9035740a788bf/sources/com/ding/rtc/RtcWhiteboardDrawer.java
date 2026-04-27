package com.ding.rtc;

import android.content.Context;
import android.content.DialogInterface;
import android.view.View;
import android.widget.PopupWindow;
import com.ding.rtc.RtcWhiteboardGestureHandler;
import com.ding.rtc.api.DingRtcWhiteBoardTypes;
import com.king.zxing.util.LogUtils;
import com.litesuits.orm.db.assit.SQLBuilder;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes.dex */
class RtcWhiteboardDrawer {
    private String TAG;
    private final Callback mCallback;
    private RtcWhiteboardGestureHandler mGestureHandler;
    private final long mNativeHandle;
    private RtcWhiteboardTextDialog mTextDialog;
    private RtcWhiteboardTextPopup mTextPopup;
    private final int mType;
    private View mWbView;
    private boolean mSkipAction = false;
    private boolean mCancelText = true;
    private boolean mSelectDClickEnable = true;
    private boolean mUseGestureHandlerRooms = false;
    private DingRtcWhiteBoardTypes.DingRtcWBGestureConfig mWBScaleGestureConfig = null;
    private boolean mPalmEraserEnabled = false;

    public interface Callback {
        void onActionBegin();

        void onActionEnd();

        void onActionMove(float x, float y);

        void onGestureHandlerAdd(RtcWhiteboardGestureHandler gesHandler);

        void onGestureHandlerRemove();
    }

    native int nativeActionBegin(long nativeHandle, int type, float x, float y);

    native int nativeActionCancel(long nativeHandle, int type);

    native int nativeActionClicked(long nativeHandle, int type, float x, float y);

    native int nativeActionDClicked(long nativeHandle, int type, float x, float y);

    native int nativeActionDrag(long nativeHandle, int type, float x, float y, float dx, float dy);

    native int nativeActionEnd(long nativeHandle, int type, float x, float y);

    native int nativeActionMove(long nativeHandle, int type, float x, float y, float dx, float dy);

    native int nativeActionPalmBegin(long nativeHandle, int type, float x, float y, float size);

    native int nativeActionPalmEnd(long nativeHandle, int type, float x, float y);

    native int nativeActionPalmMove(long nativeHandle, int type, float x, float y);

    native int nativeActionRClicked(long nativeHandle, int type, float x, float y);

    native int nativeActionScale(long nativeHandle, int type, float factor, float cx, float cy);

    native int nativeActionScroll(long nativeHandle, int type, float x, float y, float dx, float dy);

    native int nativeDetectSelectText(long nativeHandle, int type, float x, float y, RtcWhiteboardTextObject text);

    native int nativeDrawText(long nativeHandle, int type, RtcWhiteboardTextObject text);

    native int nativeEditText(long nativeHandle, int type, RtcWhiteboardTextObject text);

    native int nativeGetTextFormat(long nativeHandle, int type, RtcWhiteboardTextFormat format);

    native int nativeGetToolboxType(long nativeHandle, int type);

    public RtcWhiteboardDrawer(long nativeHandle, int type, Callback cb) {
        this.TAG = "";
        this.mNativeHandle = nativeHandle;
        this.mType = type;
        this.mCallback = cb;
        this.TAG = "Drawer(" + type + "@" + hashCode() + SQLBuilder.PARENTHESES_RIGHT;
    }

    void setSelectDClickEnable(boolean enable) {
        this.mSelectDClickEnable = enable;
    }

    void setGestureConfigurable(boolean enable, DingRtcWhiteBoardTypes.DingRtcWBGestureConfig config) {
        this.mUseGestureHandlerRooms = enable;
        this.mWBScaleGestureConfig = config;
        if (config != null) {
            setEnablePalmEraser(config.palmEnabled);
        }
    }

    void setEnablePalmEraser(boolean enable) {
        this.mPalmEraserEnabled = enable;
        RtcWhiteboardGestureHandler rtcWhiteboardGestureHandler = this.mGestureHandler;
        if (rtcWhiteboardGestureHandler != null) {
            rtcWhiteboardGestureHandler.setEnablePalmEraser(enable);
        }
    }

    public void start(Context context, View view) {
        Logging.i(this.TAG, "RtcWbDrawer start");
        RtcWhiteboardGestureHandler.Callback callback = new RtcWhiteboardGestureHandler.Callback() { // from class: com.ding.rtc.RtcWhiteboardDrawer.1
            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onBegin(float x, float y) {
                Logging.i(RtcWhiteboardDrawer.this.TAG, "onBegin x:" + x + ", y:" + y);
                RtcWhiteboardDrawer.this.mSkipAction = false;
                RtcWhiteboardDrawer.this.mCallback.onActionBegin();
                RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                if (rtcWhiteboardDrawer.nativeGetToolboxType(rtcWhiteboardDrawer.mNativeHandle, RtcWhiteboardDrawer.this.mType) == DingRtcWhiteBoardTypes.DingRtcWBToolType.TEXT.ordinal()) {
                    RtcWhiteboardDrawer.this.mSkipAction = true;
                    RtcWhiteboardDrawer.this.doTextInput_d((int) x, (int) y);
                } else {
                    RtcWhiteboardDrawer rtcWhiteboardDrawer2 = RtcWhiteboardDrawer.this;
                    rtcWhiteboardDrawer2.nativeActionBegin(rtcWhiteboardDrawer2.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y);
                }
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onClicked(float x, float y) {
                Logging.i(RtcWhiteboardDrawer.this.TAG, "onClicked x:" + x + ", y:" + y);
                if (!RtcWhiteboardDrawer.this.mSkipAction) {
                    RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                    rtcWhiteboardDrawer.nativeActionClicked(rtcWhiteboardDrawer.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y);
                    RtcWhiteboardDrawer rtcWhiteboardDrawer2 = RtcWhiteboardDrawer.this;
                    rtcWhiteboardDrawer2.nativeActionEnd(rtcWhiteboardDrawer2.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y);
                }
                RtcWhiteboardDrawer.this.mCallback.onActionEnd();
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onRightClicked(float x, float y) {
                Logging.i(RtcWhiteboardDrawer.this.TAG, "onRightClicked x:" + x + ", y:" + y);
                if (!RtcWhiteboardDrawer.this.mSkipAction) {
                    RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                    rtcWhiteboardDrawer.nativeActionRClicked(rtcWhiteboardDrawer.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y);
                    RtcWhiteboardDrawer rtcWhiteboardDrawer2 = RtcWhiteboardDrawer.this;
                    rtcWhiteboardDrawer2.nativeActionEnd(rtcWhiteboardDrawer2.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y);
                }
                RtcWhiteboardDrawer.this.mCallback.onActionEnd();
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onDoubleClicked(float x, float y) {
                Logging.i(RtcWhiteboardDrawer.this.TAG, "onDoubleClicked x:" + x + ", y:" + y);
                if (!RtcWhiteboardDrawer.this.mSkipAction) {
                    RtcWhiteboardTextObject textObj = new RtcWhiteboardTextObject();
                    RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                    if (rtcWhiteboardDrawer.nativeDetectSelectText(rtcWhiteboardDrawer.mNativeHandle, RtcWhiteboardDrawer.this.mType, x, y, textObj) == 0) {
                        RtcWhiteboardDrawer.this.mSkipAction = true;
                        RtcWhiteboardDrawer.this.doTextEdit_d(textObj);
                        return;
                    } else {
                        if (RtcWhiteboardDrawer.this.mSelectDClickEnable) {
                            RtcWhiteboardDrawer rtcWhiteboardDrawer2 = RtcWhiteboardDrawer.this;
                            rtcWhiteboardDrawer2.nativeActionDClicked(rtcWhiteboardDrawer2.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y);
                        }
                        RtcWhiteboardDrawer rtcWhiteboardDrawer3 = RtcWhiteboardDrawer.this;
                        rtcWhiteboardDrawer3.nativeActionEnd(rtcWhiteboardDrawer3.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y);
                    }
                }
                RtcWhiteboardDrawer.this.mCallback.onActionEnd();
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onMove(float x, float y, float dx, float dy, float vx, float vy) {
                Logging.i(RtcWhiteboardDrawer.this.TAG, "onMove: " + dx + LogUtils.COLON + dy);
                if (!RtcWhiteboardDrawer.this.mSkipAction) {
                    RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                    rtcWhiteboardDrawer.nativeActionMove(rtcWhiteboardDrawer.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y, -dx, -dy);
                }
                RtcWhiteboardDrawer.this.mCallback.onActionMove(x, y);
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onDrag(float x, float y, float dx, float dy, float vx, float vy) {
                if (!RtcWhiteboardDrawer.this.mSkipAction) {
                    RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                    rtcWhiteboardDrawer.nativeActionDrag(rtcWhiteboardDrawer.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y, dx, dy);
                }
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onScroll(float x, float y, float dx, float dy, float vx, float vy) {
                if (!RtcWhiteboardDrawer.this.mSkipAction) {
                    RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                    rtcWhiteboardDrawer.nativeActionScroll(rtcWhiteboardDrawer.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y, dx, dy);
                }
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onScale(float factor, float focusX, float focusY, float spanX, float spanY) {
                Logging.i(RtcWhiteboardDrawer.this.TAG, "onScale: " + factor + "," + focusX + "," + focusY);
                if (!RtcWhiteboardDrawer.this.mSkipAction) {
                    RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                    rtcWhiteboardDrawer.nativeActionScale(rtcWhiteboardDrawer.getNativeHandle(), RtcWhiteboardDrawer.this.mType, factor, focusX, focusY);
                }
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onEnd(float x, float y) {
                Logging.i(RtcWhiteboardDrawer.this.TAG, "onEnd x:" + x + ", y:" + y);
                if (!RtcWhiteboardDrawer.this.mSkipAction) {
                    RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                    rtcWhiteboardDrawer.nativeActionEnd(rtcWhiteboardDrawer.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y);
                }
                RtcWhiteboardDrawer.this.mCallback.onActionEnd();
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onCancel() {
                Logging.i(RtcWhiteboardDrawer.this.TAG, "onCancel");
                if (!RtcWhiteboardDrawer.this.mSkipAction) {
                    RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                    rtcWhiteboardDrawer.nativeActionCancel(rtcWhiteboardDrawer.getNativeHandle(), RtcWhiteboardDrawer.this.mType);
                }
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onPalmBegin(float x, float y, float size) {
                Logging.i(RtcWhiteboardDrawer.this.TAG, "onPalmBegin");
                RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                rtcWhiteboardDrawer.nativeActionPalmBegin(rtcWhiteboardDrawer.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y, size);
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onPalmMove(float x, float y) {
                Logging.i(RtcWhiteboardDrawer.this.TAG, "onPalmMove");
                RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                rtcWhiteboardDrawer.nativeActionPalmMove(rtcWhiteboardDrawer.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y);
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandler.Callback
            public void onPalmEnd(float x, float y) {
                Logging.i(RtcWhiteboardDrawer.this.TAG, "onPalmEnd");
                RtcWhiteboardDrawer rtcWhiteboardDrawer = RtcWhiteboardDrawer.this;
                rtcWhiteboardDrawer.nativeActionPalmEnd(rtcWhiteboardDrawer.getNativeHandle(), RtcWhiteboardDrawer.this.mType, x, y);
            }
        };
        if (this.mUseGestureHandlerRooms) {
            this.mGestureHandler = new RtcWhiteboardGestureHandlerRooms(view.getContext().getApplicationContext(), callback, this.mWBScaleGestureConfig);
        } else {
            this.mGestureHandler = new RtcWhiteboardGestureHandler(view.getContext().getApplicationContext(), callback);
        }
        this.mGestureHandler.setEnablePalmEraser(this.mPalmEraserEnabled);
        this.mCallback.onGestureHandlerAdd(this.mGestureHandler);
        this.mWbView = view;
        this.mCancelText = false;
    }

    private void doTextInput_p(int x, int y) {
        if (this.mWbView == null || this.mCancelText) {
            return;
        }
        RtcWhiteboardTextPopup rtcWhiteboardTextPopup = this.mTextPopup;
        if (rtcWhiteboardTextPopup != null && rtcWhiteboardTextPopup.isShowing()) {
            this.mTextPopup.dismiss();
            return;
        }
        RtcWhiteboardTextObject textObject = new RtcWhiteboardTextObject();
        nativeGetTextFormat(this.mNativeHandle, this.mType, textObject.format);
        RtcWhiteboardTextPopup rtcWhiteboardTextPopup2 = new RtcWhiteboardTextPopup(this.mWbView.getContext().getApplicationContext(), x, y, textObject);
        this.mTextPopup = rtcWhiteboardTextPopup2;
        rtcWhiteboardTextPopup2.setOnDismissListener(new PopupWindow.OnDismissListener() { // from class: com.ding.rtc.-$$Lambda$RtcWhiteboardDrawer$vu1VGMnkdiky2Hd1XbBqnc7JdnY
            @Override // android.widget.PopupWindow.OnDismissListener
            public final void onDismiss() {
                this.f$0.lambda$doTextInput_p$0$RtcWhiteboardDrawer();
            }
        });
        this.mTextPopup.update();
        this.mTextPopup.showAsDropDown(this.mWbView, x, y, 8388659);
    }

    public /* synthetic */ void lambda$doTextInput_p$0$RtcWhiteboardDrawer() {
        View view;
        if (this.mTextPopup != null && (view = this.mWbView) != null) {
            int[] loc = new int[2];
            view.getLocationOnScreen(loc);
            RtcWhiteboardTextObject obj = this.mTextPopup.getTextObject();
            obj.x -= loc[0];
            obj.y -= loc[1];
            this.mCallback.onActionBegin();
            nativeDrawText(this.mNativeHandle, this.mType, obj);
            this.mCallback.onActionEnd();
            this.mTextPopup = null;
        }
    }

    void doTextEdit_p(RtcWhiteboardTextObject textObject) {
        if (this.mWbView == null || this.mCancelText) {
            return;
        }
        RtcWhiteboardTextPopup rtcWhiteboardTextPopup = this.mTextPopup;
        if (rtcWhiteboardTextPopup != null && rtcWhiteboardTextPopup.isShowing()) {
            this.mTextPopup.dismiss();
            return;
        }
        int x = (int) textObject.x;
        int y = (int) textObject.y;
        RtcWhiteboardTextPopup rtcWhiteboardTextPopup2 = new RtcWhiteboardTextPopup(this.mWbView.getContext().getApplicationContext(), x, y, textObject);
        this.mTextPopup = rtcWhiteboardTextPopup2;
        rtcWhiteboardTextPopup2.setOnDismissListener(new PopupWindow.OnDismissListener() { // from class: com.ding.rtc.-$$Lambda$RtcWhiteboardDrawer$hJVMac3V49gG3NtMQaVC9GrZOH4
            @Override // android.widget.PopupWindow.OnDismissListener
            public final void onDismiss() {
                this.f$0.lambda$doTextEdit_p$1$RtcWhiteboardDrawer();
            }
        });
        this.mTextPopup.update();
        this.mTextPopup.showAsDropDown(this.mWbView, x, y, 8388659);
    }

    public /* synthetic */ void lambda$doTextEdit_p$1$RtcWhiteboardDrawer() {
        View view;
        if (this.mTextPopup != null && (view = this.mWbView) != null) {
            int[] loc = new int[2];
            view.getLocationOnScreen(loc);
            RtcWhiteboardTextObject obj = this.mTextPopup.getTextObject();
            obj.x -= loc[0];
            obj.y -= loc[1];
            nativeEditText(this.mNativeHandle, this.mType, obj);
            this.mCallback.onActionEnd();
            this.mTextPopup = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void doTextInput_d(int x, int y) {
        if (this.mWbView == null || this.mCancelText) {
            return;
        }
        RtcWhiteboardTextDialog rtcWhiteboardTextDialog = this.mTextDialog;
        if (rtcWhiteboardTextDialog != null && rtcWhiteboardTextDialog.isShowing()) {
            this.mTextDialog.dismiss();
            return;
        }
        RtcWhiteboardTextObject textObject = new RtcWhiteboardTextObject();
        nativeGetTextFormat(this.mNativeHandle, this.mType, textObject.format);
        int[] location = new int[2];
        this.mWbView.getLocationOnScreen(location);
        int yy = location[1] + y;
        if (yy < 0) {
            yy = 0;
        }
        int xx = location[0] + x;
        if (xx < 0) {
            xx = 0;
        }
        RtcWhiteboardTextDialog rtcWhiteboardTextDialog2 = new RtcWhiteboardTextDialog(this.mWbView.getContext(), xx, yy, textObject);
        this.mTextDialog = rtcWhiteboardTextDialog2;
        rtcWhiteboardTextDialog2.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: com.ding.rtc.-$$Lambda$RtcWhiteboardDrawer$dLKReRIyVvymUMDkCntZU-X6IGw
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$doTextInput_d$2$RtcWhiteboardDrawer(dialogInterface);
            }
        });
        this.mTextDialog.show();
    }

    public /* synthetic */ void lambda$doTextInput_d$2$RtcWhiteboardDrawer(DialogInterface var) {
        View view;
        if (this.mTextDialog != null && (view = this.mWbView) != null) {
            int[] loc = new int[2];
            view.getLocationOnScreen(loc);
            RtcWhiteboardTextObject obj = this.mTextDialog.getTextObject();
            obj.x -= loc[0];
            obj.y -= loc[1];
            this.mCallback.onActionBegin();
            nativeDrawText(this.mNativeHandle, this.mType, obj);
            this.mCallback.onActionEnd();
            this.mTextDialog = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void doTextEdit_d(RtcWhiteboardTextObject textObject) {
        if (this.mWbView == null || this.mCancelText) {
            return;
        }
        RtcWhiteboardTextDialog rtcWhiteboardTextDialog = this.mTextDialog;
        if (rtcWhiteboardTextDialog != null && rtcWhiteboardTextDialog.isShowing()) {
            this.mTextDialog.dismiss();
            return;
        }
        int x = (int) textObject.x;
        int y = (int) textObject.y;
        int[] location = new int[2];
        this.mWbView.getLocationOnScreen(location);
        int yy = location[1] + y;
        if (yy < 0) {
            yy = 0;
        }
        int xx = location[0] + x;
        if (xx < 0) {
            xx = 0;
        }
        RtcWhiteboardTextDialog rtcWhiteboardTextDialog2 = new RtcWhiteboardTextDialog(this.mWbView.getContext(), xx, yy, textObject);
        this.mTextDialog = rtcWhiteboardTextDialog2;
        rtcWhiteboardTextDialog2.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: com.ding.rtc.-$$Lambda$RtcWhiteboardDrawer$M7nFDppNUD3myq5lBcp_N2__sr4
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$doTextEdit_d$3$RtcWhiteboardDrawer(dialogInterface);
            }
        });
        this.mTextDialog.show();
    }

    public /* synthetic */ void lambda$doTextEdit_d$3$RtcWhiteboardDrawer(DialogInterface var) {
        View view;
        if (this.mTextDialog != null && (view = this.mWbView) != null) {
            int[] loc = new int[2];
            view.getLocationOnScreen(loc);
            RtcWhiteboardTextObject obj = this.mTextDialog.getTextObject();
            obj.x -= loc[0];
            obj.y -= loc[1];
            nativeEditText(this.mNativeHandle, this.mType, obj);
            this.mCallback.onActionEnd();
            this.mTextDialog = null;
        }
    }

    public void stop() {
        Logging.i(this.TAG, "RtcWbDrawer stop");
        this.mCancelText = true;
        try {
            if (this.mTextPopup != null && this.mTextPopup.isShowing()) {
                this.mTextPopup.dismiss();
                this.mTextPopup = null;
            }
        } catch (Exception e) {
        }
        try {
            if (this.mTextDialog != null && this.mTextDialog.isShowing()) {
                this.mTextDialog.dismiss();
                this.mTextDialog = null;
            }
        } catch (Exception e2) {
        }
        this.mCallback.onGestureHandlerRemove();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public long getNativeHandle() {
        return this.mNativeHandle;
    }
}
