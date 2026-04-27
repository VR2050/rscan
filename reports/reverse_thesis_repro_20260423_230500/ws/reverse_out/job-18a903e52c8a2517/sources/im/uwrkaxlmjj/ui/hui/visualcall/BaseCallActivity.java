package im.uwrkaxlmjj.ui.hui.visualcall;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.ServiceConnection;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.view.SurfaceView;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.Window;
import android.widget.Chronometer;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.core.app.ActivityCompat;
import com.ding.rtc.DingRtcAuthInfo;
import com.ding.rtc.DingRtcEngine;
import com.ding.rtc.DingRtcEngineEventListener;
import com.ding.rtc.DingRtcRemoteUserInfo;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.visualcall.FlowService;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.hui.visualcall.RTCAuthInfo;
import im.uwrkaxlmjj.ui.hviews.DragFrameLayout;
import java.util.Arrays;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public abstract class BaseCallActivity extends Activity {
    protected DingRtcEngine.DingRtcVideoCanvas aliVideoCanvasBig;
    protected DingRtcEngine.DingRtcVideoCanvas aliVideoCanvasSmall;
    protected String currentUid;
    protected DingRtcEngine mAliRtcEngine;
    protected LinearLayout mBigWindow;
    protected Chronometer mChronometer;
    protected DingRtcEngineEventListener mEventListener;
    protected boolean mGrantPermission;
    protected DragFrameLayout mSmallWindow;
    private String mUsername;
    protected boolean mIsAudioCapture = true;
    protected boolean mIsAudioPlay = true;
    protected RTCAuthInfo mRtcAuthInfo = new RTCAuthInfo();
    protected String mChannel = "0001";
    protected int VisualCallType = 1;
    protected FlowService myservice = null;
    protected ChartUserAdapter mUserListAdapter = new ChartUserAdapter();
    protected SurfaceView surfaceView = null;
    protected int callStyle = 2;
    protected byte mbytLocalPos = 1;
    protected boolean misConnect = false;
    protected boolean mblnOtherIsPc = false;
    protected PermissionUtils.PermissionGrant mGrant = new PermissionUtils.PermissionGrant() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.BaseCallActivity.1
        @Override // im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils.PermissionGrant
        public void onPermissionGranted(int requestCode) {
            BaseCallActivity.this.initRTCEngineAndStartPreview();
            BaseCallActivity.this.mGrantPermission = true;
            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_granted_tip", R.string.visual_call_granted_tip));
        }

        @Override // im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils.PermissionGrant
        public void onPermissionCancel() {
            AVideoCallInterface.DiscardAVideoCall(BaseCallActivity.this.getIntent().getStringExtra(TtmlNode.ATTR_ID), 0, BaseCallActivity.this.callStyle == 2);
            ToastUtils.show((CharSequence) LocaleController.getString("grant_permission", R.string.grant_permission));
            RingUtils.stopSoundPoolRing();
            BaseCallActivity.this.cancelCallingState();
            BaseCallActivity.this.finish();
        }
    };
    ServiceConnection mVideoServiceConnection = new ServiceConnection() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.BaseCallActivity.2
        @Override // android.content.ServiceConnection
        public void onServiceConnected(ComponentName name, IBinder service) {
            FlowService.MyBinder binder = (FlowService.MyBinder) service;
            BaseCallActivity.this.myservice = binder.getService();
            if (BaseCallActivity.this.mBigWindow != null) {
                BaseCallActivity.this.changePopWindow();
            }
        }

        @Override // android.content.ServiceConnection
        public void onServiceDisconnected(ComponentName name) {
        }
    };

    protected abstract void changeLocalPreview(SurfaceView surfaceView);

    protected abstract void changePopWindow();

    protected abstract void changeStatusView();

    protected abstract void initLocalView();

    protected abstract void initView();

    @Override // android.app.Activity
    protected void onDestroy() {
        super.onDestroy();
    }

    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.mRtcAuthInfo.data = new RTCAuthInfo.RTCAuthInfo_Data();
        this.mUsername = AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser().id + "";
    }

    public void setUpSplash() {
        ThreadUtils.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$BaseCallActivity$RVDHuH38YHOLvYz5coU9tMPS3mE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setUpSplash$0$BaseCallActivity();
            }
        }, 1000L);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX INFO: renamed from: requestPermission, reason: merged with bridge method [inline-methods] */
    public void lambda$setUpSplash$0$BaseCallActivity() {
        PermissionUtils.requestMultiPermissions(this, new String[]{"android.permission.CAMERA", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.RECORD_AUDIO", PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, this.mGrant);
    }

    protected void showPermissionErrorAlert(String message) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(message);
        builder.setNegativeButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$BaseCallActivity$vdI2_hN3T38f9UPH-O2jBU_CbqQ
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showPermissionErrorAlert$1$BaseCallActivity(dialogInterface, i);
            }
        });
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        builder.show();
    }

    public /* synthetic */ void lambda$showPermissionErrorAlert$1$BaseCallActivity(DialogInterface dialog, int which) {
        try {
            Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
            intent.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
            startActivity(intent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    protected void initRTCEngineAndStartPreview() {
        if (checkPermission("android.permission.CAMERA") || checkPermission("android.permission.RECORD_AUDIO")) {
            setUpSplash();
            this.mGrantPermission = false;
            return;
        }
        this.mGrantPermission = true;
        if (this.mAliRtcEngine == null) {
            DingRtcEngine dingRtcEngineCreate = DingRtcEngine.create(getApplicationContext(), "");
            this.mAliRtcEngine = dingRtcEngineCreate;
            dingRtcEngineCreate.subscribeAllRemoteAudioStreams(true);
            this.mAliRtcEngine.subscribeAllRemoteVideoStreams(true);
            this.mAliRtcEngine.setRemoteDefaultVideoStreamType(DingRtcEngine.DingRtcVideoStreamType.DingRtcVideoStreamTypeFHD);
            this.mAliRtcEngine.setRtcEngineEventListener(this.mEventListener);
        }
        if (this.callStyle == 2) {
            this.mAliRtcEngine.publishLocalVideoStream(true);
            initLocalView();
            startPreview();
        }
        this.mAliRtcEngine.publishLocalAudioStream(true);
    }

    private void startPreview() {
        DingRtcEngine dingRtcEngine = this.mAliRtcEngine;
        if (dingRtcEngine == null) {
            return;
        }
        try {
            dingRtcEngine.startPreview();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected boolean checkPermission(String permission) {
        try {
            int i = ActivityCompat.checkSelfPermission(this, permission);
            if (i != 0) {
                return true;
            }
            return false;
        } catch (RuntimeException e) {
            return true;
        }
    }

    protected void cancelCallingState() {
        if (ApplicationLoader.mbytAVideoCallBusy != 0) {
            ApplicationLoader.mbytAVideoCallBusy = (byte) 0;
            ReleaseRtcCall();
        }
    }

    protected void openJoinChannelBeforeNeedParams() {
        StringBuilder sb = new StringBuilder();
        sb.append("---------cuizi ");
        sb.append(this.mAliRtcEngine == null);
        KLog.d(sb.toString());
        DingRtcEngine dingRtcEngine = this.mAliRtcEngine;
        if (dingRtcEngine != null) {
            dingRtcEngine.publishLocalAudioStream(true);
            this.mAliRtcEngine.startAudioCapture();
            if (this.mIsAudioPlay) {
                this.mAliRtcEngine.startAudioPlayer();
            } else {
                this.mAliRtcEngine.stopAudioPlayer();
            }
            if (!this.mAliRtcEngine.isSpeakerphoneEnabled() && this.callStyle == 2) {
                this.mAliRtcEngine.enableSpeakerphone(true);
            }
        }
    }

    protected void joinChannel() {
        if (this.mAliRtcEngine == null) {
            return;
        }
        DingRtcAuthInfo userInfo = new DingRtcAuthInfo();
        userInfo.appId = this.mRtcAuthInfo.data.appid;
        userInfo.userId = this.mRtcAuthInfo.data.userid;
        userInfo.gslbServer = Arrays.toString(this.mRtcAuthInfo.data.gslb);
        userInfo.token = this.mRtcAuthInfo.data.token;
        userInfo.channelId = this.mChannel;
        this.mAliRtcEngine.joinChannel(userInfo, this.mUsername);
        Log.d("--------", "=======");
    }

    protected void processOccurError(int error) {
        if (error == 16908812 || error == 33620229) {
            noSessionExit(error);
        }
    }

    protected void noSessionExit(int error) {
        runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$BaseCallActivity$KgEfxlcbmSC30beUnb47Oq6XKyE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$noSessionExit$2$BaseCallActivity();
            }
        });
    }

    public /* synthetic */ void lambda$noSessionExit$2$BaseCallActivity() {
        DingRtcEngine dingRtcEngine = this.mAliRtcEngine;
        if (dingRtcEngine != null) {
            dingRtcEngine.leaveChannel();
            this.mAliRtcEngine.destroy();
            this.mAliRtcEngine = null;
        }
        DingRtcEngine dingRtcEngineCreate = DingRtcEngine.create(getApplicationContext(), "");
        this.mAliRtcEngine = dingRtcEngineCreate;
        dingRtcEngineCreate.subscribeAllRemoteAudioStreams(true);
        this.mAliRtcEngine.subscribeAllRemoteVideoStreams(true);
        this.mAliRtcEngine.setRemoteDefaultVideoStreamType(DingRtcEngine.DingRtcVideoStreamType.DingRtcVideoStreamTypeFHD);
        DingRtcEngine dingRtcEngine2 = this.mAliRtcEngine;
        if (dingRtcEngine2 != null) {
            dingRtcEngine2.setRtcEngineEventListener(this.mEventListener);
            if (this.callStyle == 2) {
                this.mAliRtcEngine.publishLocalVideoStream(true);
                startPreview();
            }
            this.mAliRtcEngine.publishLocalAudioStream(true);
            openJoinChannelBeforeNeedParams();
            joinChannel();
        }
    }

    public void startVideoService() {
        try {
            moveTaskToBack(true);
            Intent intent = new Intent(this, (Class<?>) FlowService.class);
            this.misConnect = bindService(intent, this.mVideoServiceConnection, 1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void updateRemoteDisplay(final String uid, final int vt) {
        runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$BaseCallActivity$Vp6xSUd_ESdnI71MdKWXrf4C158
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateRemoteDisplay$3$BaseCallActivity(uid, vt);
            }
        });
    }

    public /* synthetic */ void lambda$updateRemoteDisplay$3$BaseCallActivity(String uid, int vt) {
        DingRtcEngine.DingRtcVideoCanvas cameraCanvas;
        DingRtcEngine.DingRtcVideoCanvas screenCanvas;
        DingRtcEngine dingRtcEngine = this.mAliRtcEngine;
        if (dingRtcEngine == null) {
            return;
        }
        DingRtcRemoteUserInfo remoteUserInfo = dingRtcEngine.getUserInfo(uid);
        if (remoteUserInfo == null) {
            Log.e("视频", "updateRemoteDisplay remoteUserInfo = null, uid = " + uid);
            return;
        }
        DingRtcEngine.DingRtcVideoCanvas cameraCanvas2 = remoteUserInfo.getCameraCanvas();
        DingRtcEngine.DingRtcVideoCanvas screenCanvas2 = remoteUserInfo.getScreenCanvas();
        if (vt == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackNo.getValue()) {
            cameraCanvas = null;
            screenCanvas = null;
        } else if (vt == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera.getValue()) {
            screenCanvas = null;
            cameraCanvas = createCanvasIfNull(cameraCanvas2);
            this.mAliRtcEngine.setRemoteViewConfig(cameraCanvas, uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
        } else if (vt == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen.getValue()) {
            cameraCanvas = null;
            screenCanvas = createCanvasIfNull(screenCanvas2);
            this.mAliRtcEngine.setRemoteViewConfig(screenCanvas, uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen);
        } else if (vt == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackBoth.getValue()) {
            cameraCanvas = createCanvasIfNull(cameraCanvas2);
            this.mAliRtcEngine.setRemoteViewConfig(cameraCanvas, uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
            screenCanvas = createCanvasIfNull(screenCanvas2);
            this.mAliRtcEngine.setRemoteViewConfig(screenCanvas, uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackBoth);
        } else {
            return;
        }
        ChartUserBean chartUserBean = convertRemoteUserInfo(remoteUserInfo, cameraCanvas, screenCanvas);
        if (chartUserBean.mCameraSurface != null) {
            KLog.d("---------mScreenSurface");
            ViewParent parent = chartUserBean.mCameraSurface.getParent();
            if (parent != null && (parent instanceof FrameLayout)) {
                ((FrameLayout) parent).removeAllViews();
            }
            if (this.callStyle == 2) {
                changeLocalPreview(chartUserBean.mCameraSurface);
            }
        }
    }

    private void createLocalVideoView(ViewGroup v) {
        v.removeAllViews();
        if (this.surfaceView == null) {
            this.surfaceView = new SurfaceView(this);
        }
        this.surfaceView.setZOrderOnTop(true);
        this.surfaceView.setZOrderMediaOverlay(true);
        DingRtcEngine.DingRtcVideoCanvas aliVideoCanvas = new DingRtcEngine.DingRtcVideoCanvas();
        v.addView(this.surfaceView, new ViewGroup.LayoutParams(-1, -1));
        aliVideoCanvas.view = this.surfaceView;
        aliVideoCanvas.renderMode = DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto;
        DingRtcEngine dingRtcEngine = this.mAliRtcEngine;
        if (dingRtcEngine != null) {
            dingRtcEngine.setLocalViewConfig(aliVideoCanvas, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
            this.mAliRtcEngine.startPreview();
        }
        v.getChildAt(0).setVisibility(0);
    }

    private ChartUserBean convertRemoteUserInfo(DingRtcRemoteUserInfo remoteUserInfo, DingRtcEngine.DingRtcVideoCanvas cameraCanvas, DingRtcEngine.DingRtcVideoCanvas screenCanvas) {
        String uid = remoteUserInfo.getUserID();
        ChartUserBean ret = this.mUserListAdapter.createDataIfNull(uid);
        ret.mUserId = remoteUserInfo.getUserID();
        ret.mUserName = remoteUserInfo.getDisplayName();
        ret.mCameraSurface = cameraCanvas != null ? (SurfaceView) cameraCanvas.view : null;
        ret.mIsCameraFlip = cameraCanvas != null && cameraCanvas.mirrorMode == DingRtcEngine.DingRtcRenderMirrorMode.DingRtcRenderMirrorModeAllEnabled;
        ret.mScreenSurface = screenCanvas != null ? (SurfaceView) screenCanvas.view : null;
        ret.mIsScreenFlip = screenCanvas != null && screenCanvas.mirrorMode == DingRtcEngine.DingRtcRenderMirrorMode.DingRtcRenderMirrorModeAllEnabled;
        return ret;
    }

    private DingRtcEngine.DingRtcVideoCanvas createCanvasIfNull(DingRtcEngine.DingRtcVideoCanvas canvas) {
        if (canvas == null || canvas.view == null) {
            canvas = new DingRtcEngine.DingRtcVideoCanvas();
            SurfaceView surfaceView = this.mAliRtcEngine.createRenderSurfaceView(this);
            surfaceView.setZOrderOnTop(false);
            surfaceView.setZOrderMediaOverlay(false);
            canvas.view = surfaceView;
            canvas.renderMode = DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto;
        }
        if (this.mblnOtherIsPc) {
            canvas.renderMode = DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto;
        }
        return canvas;
    }

    protected void addRemoteUser(String uid) {
        DingRtcRemoteUserInfo remoteUserInfo;
        DingRtcEngine dingRtcEngine = this.mAliRtcEngine;
        if (dingRtcEngine != null && (remoteUserInfo = dingRtcEngine.getUserInfo(uid)) != null) {
            ChartUserBean data = convertRemoteUserToUserData(remoteUserInfo);
            KLog.d("---------addRemoteUser-" + data.mCameraSurface + "   " + data.mScreenSurface);
            if (data.mCameraSurface != null) {
                KLog.d("---------addRemoteUser");
                ViewParent parent = data.mCameraSurface.getParent();
                if (parent != null && (parent instanceof FrameLayout)) {
                    ((FrameLayout) parent).removeAllViews();
                }
                if (this.callStyle == 2) {
                    changeLocalPreview(convertRemoteUserToUserData(remoteUserInfo).mCameraSurface);
                }
            }
        }
    }

    private ChartUserBean convertRemoteUserToUserData(DingRtcRemoteUserInfo remoteUserInfo) {
        String uid = remoteUserInfo.getUserID();
        ChartUserBean ret = this.mUserListAdapter.createDataIfNull(uid);
        ret.mUserId = uid;
        ret.mUserName = remoteUserInfo.getDisplayName();
        ret.mIsCameraFlip = false;
        ret.mIsScreenFlip = false;
        return ret;
    }

    protected void setFullScreen() {
        requestWindowFeature(1);
        setTheme(2131755390);
        if (Build.VERSION.SDK_INT >= 21) {
            try {
                setTaskDescription(new ActivityManager.TaskDescription((String) null, (Bitmap) null, Theme.getColor(Theme.key_actionBarDefault) | (-16777216)));
            } catch (Exception e) {
            }
            try {
                getWindow().setNavigationBarColor(-16777216);
            } catch (Exception e2) {
            }
        }
        getWindow().setBackgroundDrawableResource(R.drawable.transparent);
        if (Build.VERSION.SDK_INT >= 21) {
            Window window = getWindow();
            window.getDecorView().setSystemUiVisibility(1280);
            window.setStatusBarColor(0);
        }
    }

    protected void ReleaseRtcCall() {
        if (this.mAliRtcEngine == null) {
            return;
        }
        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$BaseCallActivity$77EIsWzeWzAxiT-RfMm5vG3PipU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$ReleaseRtcCall$4$BaseCallActivity();
            }
        }).start();
        ConnectionsManager.getInstance(UserConfig.selectedAccount).setAppPaused(true, false);
    }

    public /* synthetic */ void lambda$ReleaseRtcCall$4$BaseCallActivity() {
        this.mAliRtcEngine.setRtcEngineEventListener(null);
        if (this.callStyle == 2) {
            this.mAliRtcEngine.stopPreview();
        }
        this.mAliRtcEngine.leaveChannel();
        this.mAliRtcEngine.destroy();
        this.mAliRtcEngine = null;
    }
}
