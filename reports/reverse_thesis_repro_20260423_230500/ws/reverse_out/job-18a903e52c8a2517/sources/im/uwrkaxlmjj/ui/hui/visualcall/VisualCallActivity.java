package im.uwrkaxlmjj.ui.hui.visualcall;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.media.SoundPool;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;
import android.view.SurfaceView;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.Window;
import android.widget.Chronometer;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;
import androidx.core.app.ActivityCompat;
import androidx.recyclerview.widget.DefaultItemAnimator;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;
import com.blankj.utilcode.constant.TimeConstants;
import com.ding.rtc.DingRtcAuthInfo;
import com.ding.rtc.DingRtcEngine;
import com.ding.rtc.DingRtcEngineEventListener;
import com.ding.rtc.DingRtcRemoteUserInfo;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.google.android.exoplayer2.upstream.DefaultLoadErrorHandlingPolicy;
import com.king.zxing.util.LogUtils;
import com.socks.library.KLog;
import ezy.assist.compat.SettingsCompat;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCCall;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ColorTextView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface;
import im.uwrkaxlmjj.ui.hui.visualcall.BaseRecyclerViewAdapter;
import im.uwrkaxlmjj.ui.hui.visualcall.CallNetWorkReceiver;
import im.uwrkaxlmjj.ui.hui.visualcall.ChartUserAdapter;
import im.uwrkaxlmjj.ui.hui.visualcall.FlowService;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.hui.visualcall.RTCAuthInfo;
import im.uwrkaxlmjj.ui.hviews.DragFrameLayout;
import im.uwrkaxlmjj.ui.hviews.dialogs.Util;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import im.uwrkaxlmjj.ui.hviews.helper.MryDeviceHelper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Timer;
import java.util.TimerTask;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONException;
import org.json.JSONObject;
import org.webrtc.alirtcInterface.ALI_RTC_INTERFACE;

/* JADX INFO: loaded from: classes5.dex */
public class VisualCallActivity extends Activity implements NotificationCenter.NotificationCenterDelegate {
    private static final String TAG = VisualCallActivity.class.getName();
    TLRPC.InputPeer ChannelPeer;
    protected DingRtcEngine.DingRtcVideoCanvas aliVideoCanvasBig;
    protected DingRtcEngine.DingRtcVideoCanvas aliVideoCanvasSmall;
    private CallNetWorkReceiver callNetWorkReceiver;

    @BindView(R.attr.chart_content_userlist)
    RecyclerView chartUserListView;

    @BindView(R.attr.chart_video_container)
    DragFrameLayout chart_video_container;

    @BindView(R.attr.chr_visualcall_time)
    Chronometer chrVisualcallTime;
    public String currentUid;
    DynamicPoint dynamicPoint;

    @BindView(R.attr.img_user_head)
    BackupImageView imgUserHead;

    @BindView(R.attr.img_video_user_head)
    BackupImageView imgVideoUserHead;

    @BindView(R.attr.img_visualcall)
    ImageView imgVisualcall;

    @BindView(R.attr.img_operate_a)
    ImageView img_operate_a;

    @BindView(R.attr.img_operate_b)
    ImageView img_operate_b;

    @BindView(R.attr.img_operate_c)
    ImageView img_operate_c;

    @BindView(R.attr.img_pre_receive)
    ImageView img_pre_receive;

    @BindView(R.attr.lin_operate_a)
    LinearLayout lin_operate_a;

    @BindView(R.attr.lin_operate_b)
    LinearLayout lin_operate_b;

    @BindView(R.attr.lin_operate_c)
    LinearLayout lin_operate_c;

    @BindView(R.attr.ll_big_remote_view)
    LinearLayout llBigRemoteView;

    @BindView(R.attr.ll_big_window)
    LinearLayout llBigWindow;

    @BindView(R.attr.ll_small_remote_view)
    LinearLayout llSmallRemoteView;
    private DingRtcEngine mAliRtcEngine;
    protected Context mContext;
    private Intent mForeServiceIntent;
    private boolean mGrantPermission;
    private SurfaceView mLocalView;
    ArrayList<TLRPC.InputPeer> mUserArray;
    private ChartUserAdapter mUserListAdapter;
    private String mUsername;
    private long mlTipShow;

    @BindView(R.attr.rel_video_user)
    RelativeLayout rel_video_user;

    @BindView(R.attr.rel_visual_call_a)
    LinearLayout rel_visual_call_a;

    @BindView(R.attr.rel_visual_call_b)
    RelativeLayout rel_visual_call_b;

    @BindView(R.attr.rel_voice_user)
    RelativeLayout rel_voice_user;
    private SurfaceView sfSmallView;
    protected SoundPool soundPool;
    protected int spConnectingId;

    @BindView(R.attr.txt_call_name)
    TextView txtCallName;

    @BindView(R.attr.txt_call_status)
    ColorTextView txtCallStatus;

    @BindView(R.attr.txt_tip)
    TextView txtTip;

    @BindView(R.attr.txt_video_name)
    TextView txtVideoName;

    @BindView(R.attr.txt_video_status)
    ColorTextView txtVideoStatus;

    @BindView(R.attr.txt_visualcall_status)
    ColorTextView txtVisualcallStatus;

    @BindView(R.attr.txt_operate_a)
    ColorTextView txt_operate_a;

    @BindView(R.attr.txt_operate_b)
    ColorTextView txt_operate_b;

    @BindView(R.attr.txt_operate_c)
    ColorTextView txt_operate_c;

    @BindView(R.attr.txt_pre_change_to_voice)
    TextView txt_pre_change_to_voice;
    protected SurfaceView surfaceView = null;
    private int VisualCallType = 1;
    private boolean misConnect = false;
    private int callStyle = 2;
    private String mChannel = "0001";
    private boolean mIsAudioCapture = true;
    private boolean mIsAudioPlay = true;
    private RTCAuthInfo mRtcAuthInfo = new RTCAuthInfo();
    private long mlStart = 0;
    private long mlLastClickTime = 0;
    protected byte mbytLocalPos = 1;
    protected boolean mBlnReceiveFeedBack = false;
    private byte mbytIsForeground = 1;
    private byte mbytExit = 0;
    private Timer timer = new Timer();
    private TimerTask timerTask = null;
    private byte REQUEST_CANCEL = -2;
    private byte VISUAL_CALL_BUSY = -3;
    private byte REQUEST_NO_ANSWER = -4;
    private byte REQUEST_NETWORK_ERROR = -5;
    private int miCallReceiverId = -1;
    private boolean mblnResetNoAnswer = false;
    private boolean mblnUnProcessChooseVoiceTip = false;
    private byte mbytLastClickIndex = -1;
    private boolean mblnOtherIsPc = false;
    private byte mbytFPacketRecCount = 0;
    private ChartUserAdapter.OnSubConfigChangeListener mOnSubConfigChangeListener = new ChartUserAdapter.OnSubConfigChangeListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.5
        @Override // im.uwrkaxlmjj.ui.hui.visualcall.ChartUserAdapter.OnSubConfigChangeListener
        public void onFlipView(String uid, int flag, boolean flip) {
            DingRtcEngine.DingRtcVideoCanvas cameraCanvas;
            DingRtcEngine.DingRtcVideoCanvas screenCanvas;
            DingRtcRemoteUserInfo userInfo = VisualCallActivity.this.mAliRtcEngine.getUserInfo(uid);
            if (flag == 1001) {
                if (userInfo != null && (cameraCanvas = userInfo.getCameraCanvas()) != null) {
                    cameraCanvas.mirrorMode = flip ? DingRtcEngine.DingRtcRenderMirrorMode.DingRtcRenderMirrorModeAllEnabled : DingRtcEngine.DingRtcRenderMirrorMode.DingRtcRenderMirrorModeAllDisable;
                    VisualCallActivity.this.mAliRtcEngine.setRemoteViewConfig(cameraCanvas, uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
                    return;
                }
                return;
            }
            if (flag == 1002 && userInfo != null && (screenCanvas = userInfo.getScreenCanvas()) != null) {
                screenCanvas.mirrorMode = flip ? DingRtcEngine.DingRtcRenderMirrorMode.DingRtcRenderMirrorModeAllEnabled : DingRtcEngine.DingRtcRenderMirrorMode.DingRtcRenderMirrorModeAllDisable;
                VisualCallActivity.this.mAliRtcEngine.setRemoteViewConfig(screenCanvas, uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen);
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.visualcall.ChartUserAdapter.OnSubConfigChangeListener
        public void onShowVideoInfo(String uid, int flag) {
            DingRtcEngine.DingRtcVideoTrack dingRtcVideoTrack = DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackNo;
            if (flag == 1001) {
                DingRtcEngine.DingRtcVideoTrack track = DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera;
            } else if (flag == 1002) {
                DingRtcEngine.DingRtcVideoTrack track2 = DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen;
            }
        }
    };
    Bundle mBundle = new Bundle();
    private DingRtcEngineEventListener mEventListener = new AnonymousClass6();
    private PermissionUtils.PermissionGrant mGrant = new AnonymousClass8();
    private FlowService myservice = null;
    ServiceConnection mVideoServiceConnection = new ServiceConnection() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.9
        @Override // android.content.ServiceConnection
        public void onServiceConnected(ComponentName name, IBinder service) {
            FlowService.MyBinder binder = (FlowService.MyBinder) service;
            VisualCallActivity.this.myservice = binder.getService();
            View view = null;
            View smallView = null;
            if (VisualCallActivity.this.callStyle == 2) {
                if (VisualCallActivity.this.mbytLocalPos == 0) {
                    view = VisualCallActivity.this.mLocalView;
                } else {
                    smallView = VisualCallActivity.this.sfSmallView;
                }
                VisualCallActivity.this.llBigWindow.removeView(view);
                VisualCallActivity.this.chart_video_container.removeView(smallView);
                VisualCallActivity.this.chart_video_container.setVisibility(8);
            }
            VisualCallActivity.this.myservice.setCallStyle(VisualCallActivity.this.callStyle);
            VisualCallActivity.this.myservice.setBlnCaller(true);
            if (VisualCallActivity.this.VisualCallType == 3) {
                VisualCallActivity.this.myservice.setView(view, smallView, VisualCallActivity.this.chrVisualcallTime.getBase(), VisualCallActivity.this.mChannel);
            } else {
                VisualCallActivity.this.myservice.setView(view, smallView, -1000000L, VisualCallActivity.this.mChannel);
            }
        }

        @Override // android.content.ServiceConnection
        public void onServiceDisconnected(ComponentName name) {
        }
    };

    /* JADX INFO: Access modifiers changed from: private */
    public void changeStatusView() {
        KLog.d("--------haha callStyle" + this.callStyle + "   VisualCallType" + this.VisualCallType);
        if (this.callStyle == 1) {
            DingRtcEngine dingRtcEngine = this.mAliRtcEngine;
            if (dingRtcEngine != null && dingRtcEngine.isLocalVideoStreamPublished()) {
                KLog.d("--------关闭视频");
                this.mAliRtcEngine.publishLocalVideoStream(false);
            }
            this.chart_video_container.setVisibility(8);
            SurfaceView surfaceView = this.mLocalView;
            if (surfaceView != null) {
                surfaceView.setVisibility(8);
            }
            this.rel_video_user.setVisibility(8);
            this.rel_voice_user.setVisibility(0);
            this.txt_pre_change_to_voice.setVisibility(8);
            int i = this.VisualCallType;
            if (i == 1) {
                this.rel_visual_call_b.setVisibility(8);
                this.rel_visual_call_a.setVisibility(0);
                this.lin_operate_a.setVisibility(0);
                this.lin_operate_c.setVisibility(8);
                if (this.mIsAudioPlay) {
                    this.img_operate_a.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.visualcall_no_voice));
                } else {
                    this.img_operate_a.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.visualcall_no_voice_selected));
                }
                this.img_operate_c.setVisibility(4);
                this.txt_operate_b.setText(LocaleController.getString("Cancel", R.string.Cancel));
                return;
            }
            if (i == 2) {
                this.rel_visual_call_b.setVisibility(0);
                this.rel_visual_call_a.setVisibility(8);
                this.img_pre_receive.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.visualcall_receive_common));
                return;
            }
            this.rel_visual_call_b.setVisibility(8);
            this.rel_visual_call_a.setVisibility(0);
            this.img_operate_c.setVisibility(0);
            this.lin_operate_a.setVisibility(0);
            this.lin_operate_c.setVisibility(0);
            this.lin_operate_b.setVisibility(0);
            this.chrVisualcallTime.setVisibility(0);
            this.txtCallStatus.setVisibility(8);
            this.txt_operate_b.setText(LocaleController.getString("Str_visualcall_cancel", R.string.Str_visualcall_cancel));
            this.txt_operate_a.setText(LocaleController.getString(R.string.Str_visualcall_no_voice));
            this.txt_operate_c.setText(LocaleController.getString(R.string.Str_visualcall_hands_free));
            if (this.mIsAudioCapture) {
                this.img_operate_a.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.visualcall_no_voice));
            } else {
                this.img_operate_a.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.visualcall_no_voice_selected));
            }
            DingRtcEngine dingRtcEngine2 = this.mAliRtcEngine;
            if (dingRtcEngine2 != null) {
                if (dingRtcEngine2.isSpeakerphoneEnabled()) {
                    this.img_operate_c.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.visual_hands_free_selected));
                    return;
                } else {
                    this.img_operate_c.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.visualcall_hands_free));
                    return;
                }
            }
            return;
        }
        this.chart_video_container.setVisibility(0);
        SurfaceView surfaceView2 = this.mLocalView;
        if (surfaceView2 != null) {
            surfaceView2.setVisibility(0);
        }
        this.rel_video_user.setVisibility(0);
        this.rel_voice_user.setVisibility(8);
        DingRtcEngine dingRtcEngine3 = this.mAliRtcEngine;
        if (dingRtcEngine3 != null && !dingRtcEngine3.isLocalVideoStreamPublished()) {
            KLog.d("--------打开视频");
            this.mAliRtcEngine.publishLocalAudioStream(true);
        }
        int i2 = this.VisualCallType;
        if (i2 == 1) {
            this.rel_visual_call_b.setVisibility(8);
            this.rel_visual_call_a.setVisibility(0);
            RelativeLayout.LayoutParams params = (RelativeLayout.LayoutParams) this.txt_pre_change_to_voice.getLayoutParams();
            params.setMargins(0, 0, 0, (int) Util.dp2px(this.mContext, 200.0f));
            params.addRule(14, -1);
            params.addRule(12, -1);
            this.txt_pre_change_to_voice.setLayoutParams(params);
            this.rel_video_user.setVisibility(0);
            this.rel_voice_user.setVisibility(8);
            this.lin_operate_a.setVisibility(8);
            this.lin_operate_b.setVisibility(0);
            this.lin_operate_c.setVisibility(8);
            return;
        }
        if (i2 == 2) {
            this.rel_visual_call_b.setVisibility(0);
            RelativeLayout.LayoutParams params2 = (RelativeLayout.LayoutParams) this.txt_pre_change_to_voice.getLayoutParams();
            params2.setMargins(0, 0, (int) Util.dp2px(this.mContext, 34.0f), (int) Util.dp2px(this.mContext, 213.0f));
            params2.addRule(11, -1);
            params2.addRule(12, -1);
            this.txt_pre_change_to_voice.setLayoutParams(params2);
            this.rel_visual_call_a.setVisibility(8);
            this.img_pre_receive.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.visualcall_video_receive));
            return;
        }
        KLog.d("---------ai ");
        this.rel_visual_call_b.setVisibility(8);
        this.rel_visual_call_a.setVisibility(0);
        this.chart_video_container.setVisibility(0);
        this.txt_pre_change_to_voice.setVisibility(8);
        this.rel_video_user.setVisibility(8);
        this.rel_voice_user.setVisibility(8);
        this.lin_operate_a.setVisibility(0);
        this.lin_operate_b.setVisibility(0);
        this.lin_operate_c.setVisibility(0);
        this.img_operate_a.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.visualcall_to_voice));
        this.txt_operate_a.setText(LocaleController.getString("Str_visualcall_to_voice", R.string.Str_visualcall_to_voice));
        this.img_operate_b.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.visualcall_cancel_common));
        this.txt_operate_b.setText(LocaleController.getString("Str_visualcall_cancel", R.string.Str_visualcall_cancel));
        this.img_operate_c.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.visualcall_camera));
        this.txt_operate_c.setText(LocaleController.getString("Str_visualcall_change_camera", R.string.Str_visualcall_change_camera));
    }

    protected void regNetWorkReceiver() {
        IntentFilter filter = new IntentFilter();
        filter.addAction("android.net.conn.CONNECTIVITY_CHANGE");
        CallNetWorkReceiver callNetWorkReceiver = new CallNetWorkReceiver();
        this.callNetWorkReceiver = callNetWorkReceiver;
        registerReceiver(callNetWorkReceiver, filter);
        this.callNetWorkReceiver.setCallBack(new CallNetWorkReceiver.NetWorkStateCallBack() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.1
            @Override // im.uwrkaxlmjj.ui.hui.visualcall.CallNetWorkReceiver.NetWorkStateCallBack
            public void onNetWorkConnected() {
                if (!VisualCallActivity.this.mChannel.equals("0001")) {
                    VisualCallActivity visualCallActivity = VisualCallActivity.this;
                    visualCallActivity.sendKeepLivePacket(visualCallActivity.mChannel);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hui.visualcall.CallNetWorkReceiver.NetWorkStateCallBack
            public void onNetWorkDisconnected() {
            }
        });
    }

    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ApplicationLoader.mbytAVideoCallBusy = (byte) 2;
        setFullScreen();
        setContentView(R.layout.activity_visualcall);
        ButterKnife.bind(this);
        getWindow().addFlags(128);
        ConnectionsManager.getInstance(UserConfig.selectedAccount).setAppPaused(false, false);
        this.mContext = this;
        this.dynamicPoint = new DynamicPoint();
        initRing();
        this.chart_video_container.setY(AndroidUtilities.statusBarHeight);
        this.mRtcAuthInfo.data = new RTCAuthInfo.RTCAuthInfo_Data();
        this.mUsername = AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser().id + "";
        this.callStyle = getIntent().getIntExtra("CallType", 2);
        ArrayList<Integer> userIdArray = (ArrayList) getIntent().getSerializableExtra("ArrayUser");
        ArrayList<Integer> channelIdArray = (ArrayList) getIntent().getSerializableExtra("channel");
        KLog.d("---------VisualCallType" + this.VisualCallType + "   callStyle" + this.callStyle);
        this.mUserArray = new ArrayList<>();
        if (userIdArray != null && !userIdArray.isEmpty()) {
            Iterator<Integer> it = userIdArray.iterator();
            while (it.hasNext()) {
                int i = it.next().intValue();
                this.mUserArray.add(AccountInstance.getInstance(UserConfig.selectedAccount).getMessagesController().getInputPeer(i));
            }
            this.miCallReceiverId = userIdArray.get(0).intValue();
            setHeadImage();
        }
        if (this.callStyle == 2) {
            this.dynamicPoint.animForWaitting(LocaleController.getString("visual_call_video_waiting", R.string.visual_call_video_waiting), this.txtVideoStatus);
        } else {
            this.dynamicPoint.animForWaitting(LocaleController.getString("visual_call_waiting", R.string.visual_call_waiting), this.txtCallStatus);
        }
        regNotification();
        initRTCEngineAndStartPreview();
        this.txtTip.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(8.0f), Color.parseColor("#CB2D2D2D")));
        ChartUserAdapter chartUserAdapter = new ChartUserAdapter();
        this.mUserListAdapter = chartUserAdapter;
        chartUserAdapter.setOnSubConfigChangeListener(this.mOnSubConfigChangeListener);
        if (channelIdArray.isEmpty()) {
            this.ChannelPeer = null;
        } else {
            this.ChannelPeer = AccountInstance.getInstance(UserConfig.selectedAccount).getMessagesController().getInputPeer(channelIdArray.get(0).intValue());
        }
        if (this.mGrantPermission) {
            sendCallRequest();
        }
        changeStatusView();
        this.chrVisualcallTime.setOnChronometerTickListener(new Chronometer.OnChronometerTickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$0zNFhi4Txua9cgtLc-fdP03uB44
            @Override // android.widget.Chronometer.OnChronometerTickListener
            public final void onChronometerTick(Chronometer chronometer) {
                VisualCallActivity.lambda$onCreate$0(chronometer);
            }
        });
        this.chart_video_container.setVisibility(8);
        if (this.mGrantPermission) {
            this.chart_video_container.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$kJxeAhn9RacReqEMYEGl2tSgcJ8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onCreate$1$VisualCallActivity();
                }
            }, 35000L);
            this.img_operate_a.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$aXfaD_j4wsV31XigJ-snV9mJBVU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onCreate$2$VisualCallActivity();
                }
            }, 15000L);
        }
        regNetWorkReceiver();
    }

    static /* synthetic */ void lambda$onCreate$0(Chronometer chronometer) {
        StringBuilder sb;
        String ss;
        long time = SystemClock.elapsedRealtime() - chronometer.getBase();
        int h = (int) (time / 3600000);
        int m = ((int) (time - ((long) (h * TimeConstants.HOUR)))) / 60000;
        int s = ((int) ((time - ((long) (TimeConstants.HOUR * h))) - ((long) (60000 * m)))) / 1000;
        if (h > 0) {
            m += h * 60;
        }
        if (m < 10) {
            sb = new StringBuilder();
            sb.append("0");
            sb.append(m);
        } else {
            sb = new StringBuilder();
            sb.append(m);
            sb.append("");
        }
        String mm = sb.toString();
        if (s < 10) {
            ss = "0" + s;
        } else {
            ss = s + "";
        }
        String timeFormat = mm + LogUtils.COLON + ss;
        chronometer.setText(timeFormat);
    }

    public /* synthetic */ void lambda$onCreate$1$VisualCallActivity() {
        if (!this.mBlnReceiveFeedBack && !this.mblnResetNoAnswer) {
            processNoAnswer();
        }
    }

    public /* synthetic */ void lambda$onCreate$2$VisualCallActivity() {
        if (!this.mBlnReceiveFeedBack && !this.mblnResetNoAnswer) {
            processNoAnswerTip();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processNoAnswer() {
        int i = this.spConnectingId;
        if (i != 0) {
            this.soundPool.stop(i);
            this.spConnectingId = 0;
        }
        stopRtcAndService();
        int currentConnectionState = ConnectionsManager.getInstance(UserConfig.selectedAccount).getConnectionState();
        if (currentConnectionState == 2 || currentConnectionState == 1) {
            this.txtTip.setText(LocaleController.getString("visual_call_fail", R.string.visual_call_fail));
        } else {
            this.txtTip.setText(LocaleController.getString("visual_call_no_answer_tip", R.string.visual_call_no_answer_tip));
        }
        AVideoCallInterface.DiscardAVideoCall(this.mChannel, this.REQUEST_NO_ANSWER, this.callStyle == 2);
        this.txtTip.setVisibility(0);
        setTipPos();
        this.txtVideoStatus.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$0mmGJMuvlRtApzJukmz__IKCFW8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processNoAnswer$3$VisualCallActivity();
            }
        }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
    }

    public /* synthetic */ void lambda$processNoAnswer$3$VisualCallActivity() {
        finish();
    }

    protected void processNoAnswerTip() {
        this.txtTip.setText(LocaleController.getString("visual_call_no_answer", R.string.visual_call_no_answer));
        this.txtTip.setVisibility(0);
        setTipPos();
        this.txtCallStatus.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$qvRPNsIPNIy34A7pPGaScBYBdms
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processNoAnswerTip$4$VisualCallActivity();
            }
        }, 15000L);
    }

    public /* synthetic */ void lambda$processNoAnswerTip$4$VisualCallActivity() {
        if (!this.mBlnReceiveFeedBack) {
            this.txtTip.setVisibility(8);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity$2, reason: invalid class name */
    class AnonymousClass2 extends TimerTask {
        final /* synthetic */ String val$strId;

        AnonymousClass2(String str) {
            this.val$strId = str;
        }

        @Override // java.util.TimerTask, java.lang.Runnable
        public void run() {
            final String str = this.val$strId;
            ThreadUtils.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$2$GpuyMu3bB92aBrhNWFK7Cj0QKto
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$run$0$VisualCallActivity$2(str);
                }
            });
        }

        public /* synthetic */ void lambda$run$0$VisualCallActivity$2(String strId) {
            AVideoCallInterface.sendJumpPacket(strId, new AVideoCallInterface.AVideoRequestCallBack() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.2.1
                @Override // im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface.AVideoRequestCallBack
                public void onError(TLRPC.TL_error error) {
                }

                @Override // im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface.AVideoRequestCallBack
                public void onSuccess(TLObject object) {
                    if (object instanceof TLRPCCall.TL_MeetModel) {
                        TLRPCCall.TL_MeetModel model = (TLRPCCall.TL_MeetModel) object;
                        if (model.id.equals(VisualCallActivity.this.mChannel) && !model.video && VisualCallActivity.this.callStyle == 2) {
                            VisualCallActivity.this.callStyle = 1;
                            VisualCallActivity.this.changeToVoice(false);
                        }
                    }
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendKeepLivePacket(String strId) {
        if (this.timerTask == null) {
            AnonymousClass2 anonymousClass2 = new AnonymousClass2(strId);
            this.timerTask = anonymousClass2;
            try {
                this.timer.schedule(anonymousClass2, 14000L, 14000L);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendCallRequest() {
        AVideoCallInterface.StartAVideoCall(this.callStyle == 2, this.mUserArray, this.ChannelPeer, new AVideoCallInterface.AVideoRequestCallBack() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.3
            @Override // im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface.AVideoRequestCallBack
            public void onError(TLRPC.TL_error error) {
                if (error.text.equals("MUTUALCONTACTNEED")) {
                    VisualCallActivity.this.txtTip.setText(LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                    VisualCallActivity.this.txtTip.setVisibility(0);
                    VisualCallActivity.this.setTipPos();
                    return;
                }
                if (error.text.equals("VIDEO_RPC_ERROR")) {
                    VisualCallActivity.this.txtTip.setText(LocaleController.getString("visual_call_server_err", R.string.visual_call_server_err));
                    VisualCallActivity.this.txtTip.setVisibility(0);
                    VisualCallActivity.this.setTipPos();
                    return;
                }
                if (error.text.equals("IS_BUSYING") || error.text.equals("FROM_IS_BLOCKED") || error.text.equals("TO_IS_BLOCKED")) {
                    VisualCallActivity.this.stopRtcAndService();
                    if (VisualCallActivity.this.spConnectingId != 0) {
                        VisualCallActivity.this.soundPool.stop(VisualCallActivity.this.spConnectingId);
                        VisualCallActivity.this.spConnectingId = 0;
                    }
                    VisualCallActivity.this.mBlnReceiveFeedBack = true;
                    String str = error.text;
                    byte b = -1;
                    int iHashCode = str.hashCode();
                    if (iHashCode != -2133636844) {
                        if (iHashCode != -2013590676) {
                            if (iHashCode == 1424217083 && str.equals("TO_IS_BLOCKED")) {
                                b = 2;
                            }
                        } else if (str.equals("FROM_IS_BLOCKED")) {
                            b = 1;
                        }
                    } else if (str.equals("IS_BUSYING")) {
                        b = 0;
                    }
                    if (b == 0) {
                        VisualCallActivity.this.txtTip.setText(LocaleController.getString(R.string.visual_call_other_calling));
                    } else if (b == 1) {
                        VisualCallActivity.this.txtTip.setText(LocaleController.getString(R.string.visual_call_block_tip));
                    } else if (b == 2) {
                        VisualCallActivity.this.txtTip.setText(LocaleController.getString(R.string.visual_call_blocked_tip));
                    }
                    VisualCallActivity.this.txtTip.setVisibility(0);
                    VisualCallActivity.this.setTipPos();
                    VisualCallActivity.this.txtTip.postDelayed(new $$Lambda$tblfo3UtLqYImRKxPPOpLNJO68Q(VisualCallActivity.this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface.AVideoRequestCallBack
            public void onSuccess(TLObject object) {
                TLRPCCall.TL_UpdateMeetCallWaiting res = (TLRPCCall.TL_UpdateMeetCallWaiting) object;
                KLog.d("call id === " + res.id);
                VisualCallActivity.this.mChannel = res.id;
                VisualCallActivity.this.mRtcAuthInfo.data.appid = res.appid;
                VisualCallActivity.this.mRtcAuthInfo.data.token = res.token;
                VisualCallActivity.this.mRtcAuthInfo.data.userid = String.valueOf(AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser().id);
                String[] strArr = new String[res.gslb.size()];
                int i = 0;
                for (String strServer : res.gslb) {
                    strArr[i] = strServer;
                    i++;
                }
                VisualCallActivity.this.mRtcAuthInfo.data.gslb = strArr;
                if (res.data != null) {
                    try {
                        JSONObject jsonObject = new JSONObject(res.data.data);
                        VisualCallActivity.this.mRtcAuthInfo.data.timestamp = jsonObject.getLong("time_stamp");
                        VisualCallActivity.this.mRtcAuthInfo.data.setNonce(jsonObject.getString("nonce"));
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }
                }
                VisualCallActivity visualCallActivity = VisualCallActivity.this;
                visualCallActivity.sendKeepLivePacket(visualCallActivity.mChannel);
            }
        });
    }

    private void initRing() {
        SoundPool soundPool = new SoundPool(1, 0, 0);
        this.soundPool = soundPool;
        this.spConnectingId = soundPool.load(this, R.raw.voip_ringback, 1);
        this.soundPool.setOnLoadCompleteListener(new SoundPool.OnLoadCompleteListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$I63DlKbwveTO2PhfdR13vX2q-GQ
            @Override // android.media.SoundPool.OnLoadCompleteListener
            public final void onLoadComplete(SoundPool soundPool2, int i, int i2) {
                this.f$0.lambda$initRing$5$VisualCallActivity(soundPool2, i, i2);
            }
        });
    }

    public /* synthetic */ void lambda$initRing$5$VisualCallActivity(SoundPool soundPool, int sampleId, int status) {
        soundPool.play(this.spConnectingId, 1.0f, 1.0f, 0, -1, 1.0f);
    }

    private void setHeadImage() {
        if (this.miCallReceiverId == -1) {
            return;
        }
        TLRPC.User user = MessagesController.getInstance(UserConfig.selectedAccount).getUser(Integer.valueOf(this.miCallReceiverId));
        String strName = "";
        if (user != null) {
            strName = user.first_name;
        }
        AvatarDrawable avatarDrawable = new AvatarDrawable();
        avatarDrawable.setInfo(user);
        int i = this.callStyle;
        if (i == 2) {
            this.imgVideoUserHead.setRoundRadius(AndroidUtilities.dp(70.0f));
            this.imgVideoUserHead.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
            this.txtVideoName.setText(strName);
        } else if (i == 1) {
            this.imgUserHead.setRoundRadius(AndroidUtilities.dp(70.0f));
            this.imgUserHead.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
            this.txtCallName.setText(strName);
        }
    }

    private void initView() {
        this.mUserListAdapter = new ChartUserAdapter();
        LinearLayoutManager layoutManager = new LinearLayoutManager(this, 0, false);
        this.chartUserListView.setLayoutManager(layoutManager);
        this.chartUserListView.addItemDecoration(new BaseRecyclerViewAdapter.DividerGridItemDecoration(getResources().getDrawable(R.drawable.chart_content_userlist_item_divider)));
        DefaultItemAnimator anim = new DefaultItemAnimator();
        anim.setSupportsChangeAnimations(false);
        this.chartUserListView.setItemAnimator(anim);
        this.chartUserListView.setAdapter(this.mUserListAdapter);
        this.mUserListAdapter.setOnSubConfigChangeListener(this.mOnSubConfigChangeListener);
        this.chartUserListView.addOnChildAttachStateChangeListener(new RecyclerView.OnChildAttachStateChangeListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.4
            @Override // androidx.recyclerview.widget.RecyclerView.OnChildAttachStateChangeListener
            public void onChildViewAttachedToWindow(View view) {
                Log.i(VisualCallActivity.TAG, "onChildViewAttachedToWindow : " + view);
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnChildAttachStateChangeListener
            public void onChildViewDetachedFromWindow(View view) {
                Log.i(VisualCallActivity.TAG, "onChildViewDetachedFromWindow : " + view);
            }
        });
        changeStatusView();
    }

    private void joinChannel() {
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

    private void openJoinChannelBeforeNeedParams() {
        DingRtcEngine dingRtcEngine = this.mAliRtcEngine;
        if (dingRtcEngine != null) {
            if (this.mIsAudioCapture) {
                dingRtcEngine.startAudioCapture();
            } else {
                dingRtcEngine.stopAudioCapture();
            }
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

    /* JADX INFO: Access modifiers changed from: private */
    public void initRTCEngineAndStartPreview() {
        if (checkPermission("android.permission.CAMERA") || checkPermission("android.permission.RECORD_AUDIO")) {
            setUpSplash();
            this.mGrantPermission = false;
            return;
        }
        this.mGrantPermission = true;
        if (this.mAliRtcEngine == null) {
            DingRtcEngine dingRtcEngineCreate = DingRtcEngine.create(this.mContext.getApplicationContext(), "");
            this.mAliRtcEngine = dingRtcEngineCreate;
            dingRtcEngineCreate.subscribeAllRemoteAudioStreams(true);
            this.mAliRtcEngine.subscribeAllRemoteVideoStreams(true);
            this.mAliRtcEngine.setRemoteDefaultVideoStreamType(DingRtcEngine.DingRtcVideoStreamType.DingRtcVideoStreamTypeFHD);
            this.mAliRtcEngine.setRtcEngineEventListener(this.mEventListener);
            if (this.callStyle == 2) {
                this.mAliRtcEngine.publishLocalVideoStream(true);
                initLocalView();
                startPreview();
            }
            this.mAliRtcEngine.publishLocalAudioStream(true);
        }
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

    private void initLocalView() {
        this.aliVideoCanvasBig = new DingRtcEngine.DingRtcVideoCanvas();
        SurfaceView surfaceViewCreateRenderSurfaceView = this.mAliRtcEngine.createRenderSurfaceView(this);
        this.mLocalView = surfaceViewCreateRenderSurfaceView;
        if (surfaceViewCreateRenderSurfaceView == null) {
            Toast.makeText(getApplicationContext(), "创建画布失败", 0).show();
        } else {
            surfaceViewCreateRenderSurfaceView.setZOrderMediaOverlay(true);
            this.aliVideoCanvasBig.view = this.mLocalView;
        }
        this.aliVideoCanvasBig.renderMode = DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto;
        this.llBigWindow.addView(this.mLocalView);
        this.aliVideoCanvasSmall = new DingRtcEngine.DingRtcVideoCanvas();
        SurfaceView surfaceViewCreateRenderSurfaceView2 = this.mAliRtcEngine.createRenderSurfaceView(this);
        this.sfSmallView = surfaceViewCreateRenderSurfaceView2;
        if (surfaceViewCreateRenderSurfaceView2 == null) {
            Toast.makeText(getApplicationContext(), "创建画布失败", 0).show();
        } else {
            surfaceViewCreateRenderSurfaceView2.setZOrderOnTop(true);
            this.aliVideoCanvasSmall.view = this.sfSmallView;
        }
        this.aliVideoCanvasSmall.renderMode = DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto;
        String largeViewUid = getIntent().getStringExtra("user_id");
        this.mAliRtcEngine.setRemoteViewConfig(this.aliVideoCanvasSmall, largeViewUid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
        this.chart_video_container.addView(this.sfSmallView);
        DingRtcEngine dingRtcEngine = this.mAliRtcEngine;
        if (dingRtcEngine != null) {
            dingRtcEngine.setLocalViewConfig(this.aliVideoCanvasBig, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
        }
    }

    @OnClick({R.attr.img_operate_b, R.attr.img_operate_a, R.attr.img_operate_c, R.attr.ll_big_window, R.attr.txt_pre_change_to_voice, R.attr.img_visualcall, R.attr.chart_video_container})
    public void onclick(View mView) {
        switch (mView.getId()) {
            case R.attr.chart_video_container /* 2131296459 */:
                if (!this.chart_video_container.isDrag()) {
                    changeLocalPreview(null);
                }
                break;
            case R.attr.img_operate_a /* 2131296681 */:
                if (this.mAliRtcEngine != null) {
                    if (this.callStyle == 2) {
                        if (this.VisualCallType == 3) {
                            this.callStyle = 1;
                            AVideoCallInterface.ChangeToVoiceCall(this.mChannel, 1 == 2);
                            if (this.mAliRtcEngine.isLocalVideoStreamPublished()) {
                                KLog.d("--------关闭视频流");
                                this.mAliRtcEngine.publishLocalVideoStream(false);
                            }
                            changeToVoice(true);
                        }
                    } else if (this.mbytLastClickIndex != 0 || System.currentTimeMillis() - this.mlLastClickTime > 500) {
                        this.mlLastClickTime = System.currentTimeMillis();
                        boolean z = !this.mIsAudioCapture;
                        this.mIsAudioCapture = z;
                        if (z) {
                            this.mAliRtcEngine.publishLocalAudioStream(true);
                            this.img_operate_a.setBackgroundResource(R.drawable.visualcall_no_voice);
                        } else {
                            this.img_operate_a.setBackgroundResource(R.drawable.visualcall_no_voice_selected);
                            this.mAliRtcEngine.publishLocalAudioStream(false);
                        }
                    }
                }
                this.mbytLastClickIndex = (byte) 0;
                break;
            case R.attr.img_operate_b /* 2131296682 */:
                Log.d("------------", "--" + this.mGrantPermission);
                if (this.img_operate_b.isEnabled()) {
                    int i = this.VisualCallType;
                    if (i == 3) {
                        AVideoCallInterface.DiscardAVideoCall(this.mChannel, ((int) (System.currentTimeMillis() - this.mlStart)) / 1000, this.callStyle == 2);
                        this.txtTip.setText(LocaleController.getString("visual_call_over", R.string.visual_call_over));
                    } else if (i == 1) {
                        this.mBlnReceiveFeedBack = true;
                        AVideoCallInterface.DiscardAVideoCall(this.mChannel, this.REQUEST_CANCEL, this.callStyle == 2);
                        int i2 = this.spConnectingId;
                        if (i2 != 0) {
                            this.soundPool.stop(i2);
                            this.spConnectingId = 0;
                        }
                        this.txtTip.setText(LocaleController.getString("visual_call_cancel", R.string.visual_call_cancel));
                    }
                    setTipPos();
                    this.mChannel = "666";
                    stopRtcAndService();
                    this.img_operate_b.setBackgroundResource(R.drawable.visualcall_cancel);
                    this.img_operate_b.setEnabled(false);
                    this.txtTip.setVisibility(0);
                    this.txtTip.postDelayed(new $$Lambda$tblfo3UtLqYImRKxPPOpLNJO68Q(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                }
                break;
            case R.attr.img_operate_c /* 2131296683 */:
                KLog.d("-------VisualCallType-" + this.VisualCallType + "   callStyle" + this.callStyle);
                if (this.VisualCallType == 3 && this.mAliRtcEngine != null && (this.mbytLastClickIndex != 1 || System.currentTimeMillis() - this.mlLastClickTime > 500)) {
                    this.mlLastClickTime = System.currentTimeMillis();
                    if (this.callStyle == 2) {
                        if (this.mAliRtcEngine.switchCamera() == 0) {
                            KLog.d("----------设置成功");
                            if (this.mAliRtcEngine.getCurrentCameraDirection() == DingRtcEngine.DingRtcCameraDirection.CAMERA_REAR) {
                                this.img_operate_c.setBackgroundResource(R.drawable.visualcall_camera_changed);
                            } else if (this.mAliRtcEngine.getCurrentCameraDirection() == DingRtcEngine.DingRtcCameraDirection.CAMERA_FRONT) {
                                this.img_operate_c.setBackgroundResource(R.drawable.visualcall_camera);
                            }
                        }
                    } else if (this.mAliRtcEngine.isSpeakerphoneEnabled()) {
                        this.img_operate_c.setBackgroundResource(R.drawable.visualcall_hands_free);
                        this.mAliRtcEngine.enableSpeakerphone(false);
                    } else {
                        this.img_operate_c.setBackgroundResource(R.drawable.visual_hands_free_selected);
                        this.mAliRtcEngine.enableSpeakerphone(true);
                    }
                }
                this.mbytLastClickIndex = (byte) 1;
                break;
            case R.attr.img_visualcall /* 2131296693 */:
                if (this.imgVisualcall.isEnabled()) {
                    if (SettingsCompat.canDrawOverlays(this)) {
                        ApplicationLoader.mbytAVideoCallBusy = (byte) 4;
                        startVideoService();
                    } else if (MryDeviceHelper.isOppo()) {
                        showPermissionErrorAlert(LocaleController.getString("PermissionPopWindowOppo", R.string.PermissionPopWindowOppo));
                    } else {
                        showPermissionErrorAlert(LocaleController.getString("PermissionPopWindow", R.string.PermissionPopWindow));
                    }
                }
                break;
            case R.attr.ll_big_window /* 2131296927 */:
                if (this.callStyle == 2 && this.VisualCallType == 3) {
                    if (this.imgVisualcall.getVisibility() == 8) {
                        this.imgVisualcall.setVisibility(0);
                        this.lin_operate_b.setVisibility(0);
                        this.lin_operate_c.setVisibility(0);
                        this.lin_operate_a.setVisibility(0);
                        this.chrVisualcallTime.setVisibility(0);
                    } else {
                        this.imgVisualcall.setVisibility(8);
                        this.lin_operate_b.setVisibility(8);
                        this.lin_operate_c.setVisibility(8);
                        this.lin_operate_a.setVisibility(8);
                        this.chrVisualcallTime.setVisibility(8);
                    }
                    break;
                }
                break;
            case R.attr.txt_pre_change_to_voice /* 2131297897 */:
                if (this.mAliRtcEngine != null) {
                    this.callStyle = 1;
                    AVideoCallInterface.ChangeToVoiceCall(this.mChannel, 1 == 2);
                    if (this.mAliRtcEngine.isLocalVideoStreamPublished()) {
                        this.mAliRtcEngine.publishLocalVideoStream(false);
                    }
                    changeToVoice(true);
                    reInstallTimer();
                }
                break;
        }
    }

    private boolean checkPermission(String permission) {
        try {
            int i = ActivityCompat.checkSelfPermission(this.mContext, permission);
            if (i != 0) {
                return true;
            }
            return false;
        } catch (RuntimeException e) {
            return true;
        }
    }

    @Override // android.app.Activity
    protected void onStop() {
        this.mbytIsForeground = AndroidUtilities.isAppOnForeground(this) ? (byte) 1 : (byte) 0;
        super.onStop();
    }

    private void showPermissionErrorAlert(String message) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(message);
        builder.setNegativeButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$y0P8DlxLm2h_nq2NcpkNgvl8Xh8
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showPermissionErrorAlert$6$VisualCallActivity(dialogInterface, i);
            }
        });
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        builder.show();
    }

    public /* synthetic */ void lambda$showPermissionErrorAlert$6$VisualCallActivity(DialogInterface dialog, int which) {
        try {
            Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
            intent.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
            startActivity(intent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity$6, reason: invalid class name */
    class AnonymousClass6 extends DingRtcEngineEventListener {
        AnonymousClass6() {
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onJoinChannelResult(final int result, String channel, String userId, int elapsed) {
            KLog.d("++++++++++成功加入房间");
            VisualCallActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$6$FnGHic81gVY_9ZJ-Nh9ya-FldGU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onJoinChannelResult$0$VisualCallActivity$6(result);
                }
            });
        }

        /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
            jadx.core.utils.exceptions.JadxRuntimeException: Can't find top splitter block for handler:B:12:0x0053
            	at jadx.core.utils.BlockUtils.getTopSplitterForHandler(BlockUtils.java:1182)
            	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.collectHandlerRegions(ExcHandlersRegionMaker.java:53)
            	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.process(ExcHandlersRegionMaker.java:38)
            	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:27)
            */
        public /* synthetic */ void lambda$onJoinChannelResult$0$VisualCallActivity$6(int r5) {
            /*
                r4 = this;
                im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity r0 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.this
                com.ding.rtc.DingRtcEngine r0 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.access$800(r0)
                r1 = 1
                r0.publishLocalAudioStream(r1)
                if (r5 != 0) goto L54
                im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity r0 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.this
                android.content.Intent r0 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.access$1900(r0)
                if (r0 != 0) goto L35
                im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity r0 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.this
                android.content.Intent r1 = new android.content.Intent
                im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity r2 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.this
                android.content.Context r2 = r2.mContext
                android.content.Context r2 = r2.getApplicationContext()
                java.lang.Class<im.uwrkaxlmjj.ui.hui.visualcall.ForegroundService> r3 = im.uwrkaxlmjj.ui.hui.visualcall.ForegroundService.class
                r1.<init>(r2, r3)
                im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.access$1902(r0, r1)
                im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity r0 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.this
                android.content.Intent r0 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.access$1900(r0)
                im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity r1 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.this
                android.os.Bundle r1 = r1.mBundle
                r0.putExtras(r1)
            L35:
                int r0 = android.os.Build.VERSION.SDK_INT     // Catch: java.lang.Exception -> L53
                r1 = 26
                if (r0 < r1) goto L47
                im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity r0 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.this     // Catch: java.lang.Exception -> L53
                im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity r1 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.this     // Catch: java.lang.Exception -> L53
                android.content.Intent r1 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.access$1900(r1)     // Catch: java.lang.Exception -> L53
                r0.startForegroundService(r1)     // Catch: java.lang.Exception -> L53
                goto L52
            L47:
                im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity r0 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.this     // Catch: java.lang.Exception -> L53
                im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity r1 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.this     // Catch: java.lang.Exception -> L53
                android.content.Intent r1 = im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.access$1900(r1)     // Catch: java.lang.Exception -> L53
                r0.startService(r1)     // Catch: java.lang.Exception -> L53
            L52:
                goto L54
            L53:
                r0 = move-exception
            L54:
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.AnonymousClass6.lambda$onJoinChannelResult$0$VisualCallActivity$6(int):void");
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onNetworkQualityChanged(final String s, final DingRtcEngine.DingRtcNetworkQuality upQuality, final DingRtcEngine.DingRtcNetworkQuality downQuality) {
            VisualCallActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$6$YF0zwLdvkW1aq3XbpP-e0yKn5BE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onNetworkQualityChanged$1$VisualCallActivity$6(upQuality, downQuality, s);
                }
            });
        }

        public /* synthetic */ void lambda$onNetworkQualityChanged$1$VisualCallActivity$6(DingRtcEngine.DingRtcNetworkQuality upQuality, DingRtcEngine.DingRtcNetworkQuality downQuality, String s) {
            if (upQuality.getValue() == ALI_RTC_INTERFACE.TransportStatus.Network_Disconnected.getValue() || downQuality.getValue() == ALI_RTC_INTERFACE.TransportStatus.Network_Disconnected.getValue()) {
                VisualCallActivity.this.mbytExit = (byte) 1;
                if (VisualCallActivity.this.VisualCallType == 3) {
                    AVideoCallInterface.DiscardAVideoCall(VisualCallActivity.this.mChannel, ((int) (System.currentTimeMillis() - VisualCallActivity.this.mlStart)) / 1000, VisualCallActivity.this.callStyle == 2);
                    VisualCallActivity.this.txtTip.setText(LocaleController.getString("visual_call_stop", R.string.visual_call_stop));
                } else if (VisualCallActivity.this.VisualCallType == 1) {
                    AVideoCallInterface.DiscardAVideoCall(VisualCallActivity.this.mChannel, VisualCallActivity.this.REQUEST_CANCEL, VisualCallActivity.this.callStyle == 2);
                    if (VisualCallActivity.this.spConnectingId != 0) {
                        VisualCallActivity.this.soundPool.stop(VisualCallActivity.this.spConnectingId);
                        VisualCallActivity.this.spConnectingId = 0;
                    }
                    VisualCallActivity.this.txtTip.setText(LocaleController.getString("visual_call_stop", R.string.visual_call_stop));
                }
                VisualCallActivity.this.stopRtcAndService();
                VisualCallActivity.this.img_operate_b.setBackgroundResource(R.drawable.visualcall_cancel);
                VisualCallActivity.this.img_operate_b.setEnabled(false);
                VisualCallActivity.this.txtTip.setVisibility(0);
                VisualCallActivity.this.txtTip.postDelayed(new $$Lambda$tblfo3UtLqYImRKxPPOpLNJO68Q(VisualCallActivity.this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            }
            if (VisualCallActivity.this.mbytExit != 1 && VisualCallActivity.this.callStyle == 2) {
                if (!s.equals(Integer.valueOf(AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser().id))) {
                    if (upQuality.getValue() > ALI_RTC_INTERFACE.TransportStatus.Network_Bad.getValue()) {
                        VisualCallActivity.this.txtTip.setText(LocaleController.getString("visual_call_other_net_bad", R.string.visual_call_other_net_bad));
                        VisualCallActivity.this.txtTip.setVisibility(0);
                        VisualCallActivity.this.mlTipShow = System.currentTimeMillis();
                        return;
                    } else {
                        if (VisualCallActivity.this.txtTip.getVisibility() == 0 && System.currentTimeMillis() - VisualCallActivity.this.mlTipShow > AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS) {
                            VisualCallActivity.this.txtTip.setVisibility(8);
                            return;
                        }
                        return;
                    }
                }
                if (downQuality.getValue() > ALI_RTC_INTERFACE.TransportStatus.Network_Bad.getValue()) {
                    VisualCallActivity.this.txtTip.setText(LocaleController.getString("visual_call_net_bad", R.string.visual_call_net_bad));
                    VisualCallActivity.this.txtTip.setVisibility(0);
                    VisualCallActivity.this.mlTipShow = System.currentTimeMillis();
                } else if (VisualCallActivity.this.txtTip.getVisibility() == 0 && System.currentTimeMillis() - VisualCallActivity.this.mlTipShow > AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS) {
                    VisualCallActivity.this.txtTip.setVisibility(8);
                }
            }
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onOccurError(int error, String message) {
            VisualCallActivity.this.processOccurError(error);
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onConnectionLost() {
            VisualCallActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$6$LFFjCLUaynFrDmaAHmsnWrktC4c
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onConnectionLost$2$VisualCallActivity$6();
                }
            });
        }

        public /* synthetic */ void lambda$onConnectionLost$2$VisualCallActivity$6() {
            VisualCallActivity.this.txtTip.setText(LocaleController.getString("visual_call_network_disconnect", R.string.visual_call_network_disconnect));
            VisualCallActivity.this.txtTip.setVisibility(0);
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onTryToReconnect() {
            VisualCallActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$6$gC3xkogscJRV7V_PDswb7M_jGX0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onTryToReconnect$3$VisualCallActivity$6();
                }
            });
        }

        public /* synthetic */ void lambda$onTryToReconnect$3$VisualCallActivity$6() {
            VisualCallActivity.this.txtTip.setText(LocaleController.getString("visual_call_retry_connect", R.string.visual_call_retry_connect));
            VisualCallActivity.this.txtTip.setVisibility(0);
        }

        public /* synthetic */ void lambda$onConnectionRecovery$4$VisualCallActivity$6() {
            VisualCallActivity.this.txtTip.setVisibility(8);
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onConnectionRecovery() {
            VisualCallActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$6$vkDGgddUGXBmRxKXN3WrAbD2_2A
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onConnectionRecovery$4$VisualCallActivity$6();
                }
            });
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onRemoteUserOffLineNotify(String uid, DingRtcEngine.DingRtcUserOfflineReason reason) {
            VisualCallActivity.this.updateRemoteDisplay(uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackNo.getValue());
            removeRemoteUser(uid);
        }

        private void removeRemoteUser(final String uid) {
            KLog.d("---------远端用户下线通知" + uid);
            VisualCallActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$6$zEPGcS4C1x0b0X5atkj38nRVcSM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$removeRemoteUser$5$VisualCallActivity$6(uid);
                }
            });
        }

        public /* synthetic */ void lambda$removeRemoteUser$5$VisualCallActivity$6(String uid) {
            VisualCallActivity.this.mUserListAdapter.removeData(uid, true);
            if (!VisualCallActivity.this.mChannel.equals("666")) {
                VisualCallActivity.this.stopRtcAndService();
                if (VisualCallActivity.this.spConnectingId != 0) {
                    VisualCallActivity.this.soundPool.stop(VisualCallActivity.this.spConnectingId);
                    VisualCallActivity.this.spConnectingId = 0;
                }
                if (VisualCallActivity.this.VisualCallType == 3) {
                    VisualCallActivity.this.txtTip.setText(LocaleController.getString("visual_call_other_side_discard", R.string.visual_call_other_side_discard));
                    VisualCallActivity.this.txtTip.setVisibility(0);
                    VisualCallActivity.this.chrVisualcallTime.stop();
                    VisualCallActivity.this.txtTip.postDelayed(new $$Lambda$tblfo3UtLqYImRKxPPOpLNJO68Q(VisualCallActivity.this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                    return;
                }
                VisualCallActivity.this.mBlnReceiveFeedBack = true;
                VisualCallActivity.this.txtTip.setText(LocaleController.getString("visual_call_other_side_refuse", R.string.visual_call_other_side_refuse));
                VisualCallActivity.this.txtTip.setVisibility(0);
                VisualCallActivity.this.txtTip.postDelayed(new $$Lambda$tblfo3UtLqYImRKxPPOpLNJO68Q(VisualCallActivity.this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            }
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onRemoteUserOnLineNotify(final String uid, int elapsed) {
            KLog.d("----------远端用户上线通知" + uid);
            if (TextUtils.isEmpty(VisualCallActivity.this.currentUid)) {
                VisualCallActivity.this.currentUid = uid;
                VisualCallActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$6$hTlvG1AuCfwLjJ9m2vYv009k5F0
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onRemoteUserOnLineNotify$7$VisualCallActivity$6(uid);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$onRemoteUserOnLineNotify$7$VisualCallActivity$6(String uid) {
            addRemoteUser(uid);
            VisualCallActivity.this.VisualCallType = 3;
            VisualCallActivity.this.imgVisualcall.setVisibility(0);
            VisualCallActivity.this.chrVisualcallTime.setVisibility(0);
            VisualCallActivity.this.chrVisualcallTime.setBase(SystemClock.elapsedRealtime());
            VisualCallActivity.this.chrVisualcallTime.start();
            VisualCallActivity.this.rel_video_user.setVisibility(8);
            VisualCallActivity.this.txtVisualcallStatus.setVisibility(0);
            VisualCallActivity.this.imgVisualcall.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$6$WzAtT7Udm8ITgA9m15ybBJ1yKaU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$6$VisualCallActivity$6();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            VisualCallActivity.this.mlStart = System.currentTimeMillis();
            if (ApplicationLoader.mbytAVideoCallBusy == 4 && VisualCallActivity.this.myservice != null) {
                VisualCallActivity.this.myservice.setView(null, null, VisualCallActivity.this.chrVisualcallTime.getBase(), VisualCallActivity.this.mChannel);
            }
            VisualCallActivity.this.changeStatusView();
        }

        public /* synthetic */ void lambda$null$6$VisualCallActivity$6() {
            VisualCallActivity.this.txtVisualcallStatus.setVisibility(8);
        }

        private void addRemoteUser(String uid) {
            DingRtcRemoteUserInfo remoteUserInfo;
            if (VisualCallActivity.this.mAliRtcEngine != null && (remoteUserInfo = VisualCallActivity.this.mAliRtcEngine.getUserInfo(uid)) != null) {
                ChartUserBean data = convertRemoteUserToUserData(remoteUserInfo);
                KLog.d("---------mScreenSurface-" + data.mCameraSurface + "   " + data.mScreenSurface);
                if (data.mCameraSurface != null) {
                    KLog.d("---------mScreenSurface");
                    ViewParent parent = data.mCameraSurface.getParent();
                    if (parent != null && (parent instanceof FrameLayout)) {
                        ((FrameLayout) parent).removeAllViews();
                    }
                    if (VisualCallActivity.this.callStyle == 2) {
                        VisualCallActivity.this.changeLocalPreview(convertRemoteUserToUserData(remoteUserInfo).mCameraSurface);
                    }
                }
            }
        }

        private ChartUserBean convertRemoteUserToUserData(DingRtcRemoteUserInfo remoteUserInfo) {
            String uid = remoteUserInfo.getUserID();
            ChartUserBean ret = VisualCallActivity.this.mUserListAdapter.createDataIfNull(uid);
            ret.mUserId = uid;
            ret.mUserName = remoteUserInfo.getDisplayName();
            ret.mIsCameraFlip = false;
            ret.mIsScreenFlip = false;
            return ret;
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onRemoteTrackAvailableNotify(String uid, DingRtcEngine.DingRtcAudioTrack audioTrack, DingRtcEngine.DingRtcVideoTrack videoTrack) {
            StringBuilder sb = new StringBuilder();
            sb.append("---------视频流变化");
            sb.append(videoTrack.getValue() == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackNo.getValue() ? "   没有视频" : "   有视频");
            KLog.d(sb.toString());
            StringBuilder sb2 = new StringBuilder();
            sb2.append("---------音频流变化");
            sb2.append(audioTrack.getValue() == DingRtcEngine.DingRtcAudioTrack.DingRtcAudioTrackNo.getValue() ? "   没有音频" : "   有音频");
            KLog.d(sb2.toString());
            VisualCallActivity.this.updateRemoteDisplay(uid, videoTrack.getValue());
            if (VisualCallActivity.this.callStyle == 2) {
                VisualCallActivity.this.chart_video_container.setVisibility(0);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processOccurError(int error) {
        if (error == 16908812 || error == 33620229) {
            noSessionExit(error);
        }
    }

    private void noSessionExit(int error) {
        runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$cTLzlVOtqGmqqusQJ0qnXkux_o0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$noSessionExit$7$VisualCallActivity();
            }
        });
    }

    public /* synthetic */ void lambda$noSessionExit$7$VisualCallActivity() {
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
        this.mAliRtcEngine.setRtcEngineEventListener(this.mEventListener);
        DingRtcEngine dingRtcEngine2 = this.mAliRtcEngine;
        if (dingRtcEngine2 != null) {
            if (this.callStyle == 2) {
                dingRtcEngine2.publishLocalVideoStream(true);
                startPreview();
            }
            this.mAliRtcEngine.publishLocalAudioStream(true);
            openJoinChannelBeforeNeedParams();
            joinChannel();
        }
    }

    @Override // android.app.Activity
    public void onBackPressed() {
        XDialog.Builder builder = new XDialog.Builder(this);
        builder.setTitle(LocaleController.getString("Tips", R.string.Tips));
        builder.setMessage(LocaleController.getString(R.string.visual_call_exit_ask));
        builder.setPositiveButton(LocaleController.getString("Set", R.string.Set), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$jCiUN--3Xj-7rUUL3nX-b9w6PVM
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$onBackPressed$8$VisualCallActivity(dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        XDialog dialog = builder.create();
        dialog.show();
    }

    public /* synthetic */ void lambda$onBackPressed$8$VisualCallActivity(DialogInterface dialogInterface, int i) {
        if (this.VisualCallType == 3) {
            AVideoCallInterface.DiscardAVideoCall(this.mChannel, ((int) (System.currentTimeMillis() - this.mlStart)) / 1000, this.callStyle == 2);
        } else {
            AVideoCallInterface.DiscardAVideoCall(this.mChannel, this.REQUEST_CANCEL, this.callStyle == 2);
        }
        stopRtcAndService();
        super.onBackPressed();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateRemoteDisplay(final String uid, final int vt) {
        runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity.7
            @Override // java.lang.Runnable
            public void run() {
                DingRtcEngine.DingRtcVideoCanvas cameraCanvas;
                DingRtcEngine.DingRtcVideoCanvas screenCanvas;
                if (VisualCallActivity.this.mAliRtcEngine != null) {
                    DingRtcRemoteUserInfo remoteUserInfo = VisualCallActivity.this.mAliRtcEngine.getUserInfo(uid);
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
                        cameraCanvas = VisualCallActivity.this.createCanvasIfNull(cameraCanvas2);
                        VisualCallActivity.this.mAliRtcEngine.setRemoteViewConfig(cameraCanvas, uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
                    } else if (vt == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen.getValue()) {
                        cameraCanvas = null;
                        screenCanvas = VisualCallActivity.this.createCanvasIfNull(screenCanvas2);
                        VisualCallActivity.this.mAliRtcEngine.setRemoteViewConfig(screenCanvas, uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen);
                    } else if (vt == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackBoth.getValue()) {
                        cameraCanvas = VisualCallActivity.this.createCanvasIfNull(cameraCanvas2);
                        VisualCallActivity.this.mAliRtcEngine.setRemoteViewConfig(cameraCanvas, uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
                        screenCanvas = VisualCallActivity.this.createCanvasIfNull(screenCanvas2);
                        VisualCallActivity.this.mAliRtcEngine.setRemoteViewConfig(screenCanvas, uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackScreen);
                    } else {
                        return;
                    }
                    ChartUserBean chartUserBean = VisualCallActivity.this.convertRemoteUserInfo(remoteUserInfo, cameraCanvas, screenCanvas);
                    if (chartUserBean.mCameraSurface != null) {
                        KLog.d("---------mScreenSurface");
                        ViewParent parent = chartUserBean.mCameraSurface.getParent();
                        if (parent != null && (parent instanceof FrameLayout)) {
                            ((FrameLayout) parent).removeAllViews();
                        }
                        if (VisualCallActivity.this.callStyle == 2) {
                            VisualCallActivity.this.changeLocalPreview(chartUserBean.mCameraSurface);
                        }
                    }
                }
            }
        });
    }

    private void createLocalVideoView(ViewGroup v) {
        v.removeAllViews();
        SurfaceView surfaceView1 = new SurfaceView(this);
        surfaceView1.setZOrderOnTop(true);
        surfaceView1.setZOrderMediaOverlay(true);
        DingRtcEngine.DingRtcVideoCanvas aliVideoCanvas = new DingRtcEngine.DingRtcVideoCanvas();
        v.addView(surfaceView1, new ViewGroup.LayoutParams(-1, -1));
        aliVideoCanvas.view = surfaceView1;
        aliVideoCanvas.renderMode = DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto;
        DingRtcEngine dingRtcEngine = this.mAliRtcEngine;
        if (dingRtcEngine != null) {
            dingRtcEngine.stopPreview();
            this.mAliRtcEngine.setLocalViewConfig(aliVideoCanvas, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
            this.mAliRtcEngine.startPreview();
        }
        v.getChildAt(0).setVisibility(0);
    }

    protected void changeLocalPreview(SurfaceView view) {
        if (view != null) {
            if (this.mbytLocalPos == 0) {
                this.mbytLocalPos = (byte) 1;
            } else {
                this.mbytLocalPos = (byte) 0;
            }
        }
        if (this.mbytLocalPos == 0) {
            this.mLocalView.setVisibility(0);
            this.llBigRemoteView.setVisibility(0);
            this.sfSmallView.setVisibility(0);
            this.llSmallRemoteView.setVisibility(8);
            View v = this.llSmallRemoteView.getChildAt(0);
            this.llSmallRemoteView.removeAllViews();
            this.llBigRemoteView.removeAllViews();
            if (view == null) {
                if (v != null) {
                    ((SurfaceView) v).setZOrderOnTop(false);
                    ((SurfaceView) v).setZOrderMediaOverlay(false);
                    this.llBigRemoteView.addView(v, new LinearLayout.LayoutParams(-1, -1));
                }
            } else {
                this.llBigRemoteView.addView(view, new LinearLayout.LayoutParams(-1, -1));
            }
            if (this.mAliRtcEngine != null) {
                this.sfSmallView.setZOrderOnTop(true);
                this.sfSmallView.setZOrderMediaOverlay(true);
                this.mAliRtcEngine.setLocalViewConfig(this.aliVideoCanvasSmall, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
                this.mAliRtcEngine.startPreview();
            }
            this.mbytLocalPos = (byte) 1;
            return;
        }
        this.mLocalView.setVisibility(0);
        this.llBigRemoteView.setVisibility(8);
        this.sfSmallView.setVisibility(0);
        this.llSmallRemoteView.setVisibility(0);
        this.llSmallRemoteView.removeAllViews();
        View v2 = this.llBigRemoteView.getChildAt(0);
        this.llBigRemoteView.removeAllViews();
        if (view == null) {
            if (v2 != null) {
                ((SurfaceView) v2).setZOrderOnTop(true);
                this.llSmallRemoteView.addView(v2, new LinearLayout.LayoutParams(-1, -1));
            }
        } else {
            view.setZOrderOnTop(true);
            view.setZOrderMediaOverlay(true);
            this.llSmallRemoteView.addView(view, new LinearLayout.LayoutParams(-1, -1));
        }
        if (this.mAliRtcEngine != null) {
            this.mLocalView.setZOrderOnTop(true);
            this.mLocalView.setZOrderMediaOverlay(true);
            this.mAliRtcEngine.setLocalViewConfig(this.aliVideoCanvasBig, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
            this.mAliRtcEngine.startPreview();
        }
        this.mbytLocalPos = (byte) 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public ChartUserBean convertRemoteUserInfo(DingRtcRemoteUserInfo remoteUserInfo, DingRtcEngine.DingRtcVideoCanvas cameraCanvas, DingRtcEngine.DingRtcVideoCanvas screenCanvas) {
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

    /* JADX INFO: Access modifiers changed from: private */
    public DingRtcEngine.DingRtcVideoCanvas createCanvasIfNull(DingRtcEngine.DingRtcVideoCanvas canvas) {
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

    @Override // android.app.Activity
    protected void onDestroy() {
        super.onDestroy();
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.receivedAVideoCallReady);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.reecivedAVideoDiscarded);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.receivedAVideoCallAccept);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.receivedAVideoCallBusy);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.receivedAVideoCallChangeVoice);
        CallNetWorkReceiver callNetWorkReceiver = this.callNetWorkReceiver;
        if (callNetWorkReceiver != null) {
            unregisterReceiver(callNetWorkReceiver);
        }
        SoundPool soundPool = this.soundPool;
        if (soundPool != null) {
            soundPool.release();
        }
        DynamicPoint dynamicPoint = this.dynamicPoint;
        if (dynamicPoint != null) {
            dynamicPoint.release();
        }
        this.timer.cancel();
        this.timer.purge();
        TimerTask timerTask = this.timerTask;
        if (timerTask != null) {
            timerTask.cancel();
        }
    }

    public void setUpSplash() {
        ThreadUtils.runOnUiThread(new $$Lambda$VisualCallActivity$nF_cb7uIbavFyfriLowdGrQzcRo(this), 1000L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void requestPermission() {
        PermissionUtils.requestMultiPermissions(this, new String[]{"android.permission.CAMERA", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.RECORD_AUDIO", PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, this.mGrant);
    }

    @Override // android.app.Activity
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == 100) {
            PermissionUtils.requestPermissionsResult(this, requestCode, permissions, grantResults, this.mGrant);
        } else {
            super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        }
    }

    @Override // android.app.Activity
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 100) {
            new Handler().postDelayed(new $$Lambda$VisualCallActivity$nF_cb7uIbavFyfriLowdGrQzcRo(this), 500L);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity$8, reason: invalid class name */
    class AnonymousClass8 implements PermissionUtils.PermissionGrant {
        AnonymousClass8() {
        }

        @Override // im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils.PermissionGrant
        public void onPermissionGranted(int requestCode) {
            VisualCallActivity.this.initRTCEngineAndStartPreview();
            VisualCallActivity.this.sendCallRequest();
            VisualCallActivity.this.chart_video_container.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$8$fonl3xXIpG2euHXTRqpro31o1TQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPermissionGranted$0$VisualCallActivity$8();
                }
            }, 35000L);
            VisualCallActivity.this.img_operate_a.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$8$qTJfN636U_aXbRXm5v2A10IsPJ8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPermissionGranted$1$VisualCallActivity$8();
                }
            }, 15000L);
        }

        public /* synthetic */ void lambda$onPermissionGranted$0$VisualCallActivity$8() {
            if (!VisualCallActivity.this.mBlnReceiveFeedBack && !VisualCallActivity.this.mblnResetNoAnswer) {
                VisualCallActivity.this.processNoAnswer();
            }
        }

        public /* synthetic */ void lambda$onPermissionGranted$1$VisualCallActivity$8() {
            if (!VisualCallActivity.this.mBlnReceiveFeedBack && !VisualCallActivity.this.mblnResetNoAnswer) {
                VisualCallActivity.this.processNoAnswerTip();
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils.PermissionGrant
        public void onPermissionCancel() {
            ToastUtils.show((CharSequence) LocaleController.getString("grant_permission", R.string.grant_permission));
            VisualCallActivity.this.stopRtcAndService();
            VisualCallActivity.this.finish();
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

    @Override // android.app.Activity
    protected void onRestart() {
        super.onRestart();
    }

    @Override // android.app.Activity
    protected void onResume() {
        super.onResume();
        KLog.d("--------------resume------------");
        if (this.mblnUnProcessChooseVoiceTip) {
            this.txtTip.setText(LocaleController.getString(R.string.visual_call_receive_to_voice));
            setTipPos();
            this.txtTip.setVisibility(0);
            this.txtTip.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$bL79lZ-QpnixOp60oGG5MhtZ9XQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onResume$9$VisualCallActivity();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            this.mblnUnProcessChooseVoiceTip = false;
        }
        FlowService flowService = this.myservice;
        if (flowService != null && this.mbytIsForeground == 1) {
            View videoView = flowService.getViewBig(false);
            View smallView = this.myservice.getViewSmall(false);
            if (this.callStyle == 2 && videoView != null) {
                if (this.VisualCallType == 3) {
                    changeLocalPreview(null);
                }
                if (this.VisualCallType == 3) {
                    changeLocalPreview(null);
                }
                this.llBigWindow.addView(videoView, new ViewGroup.LayoutParams(-1, -1));
                if (smallView != null) {
                    this.chart_video_container.addView(smallView, new ViewGroup.LayoutParams(-1, -1));
                }
                this.chart_video_container.setVisibility(0);
            }
        }
        if (this.misConnect) {
            unbindService(this.mVideoServiceConnection);
            this.misConnect = false;
        }
        this.mbytIsForeground = (byte) 1;
    }

    public /* synthetic */ void lambda$onResume$9$VisualCallActivity() {
        this.txtTip.setVisibility(8);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        TLRPCCall.TL_UpdateMeetChangeCall changeCall;
        if (id == NotificationCenter.receivedAVideoCallReady) {
            TLRPCCall.TL_UpdateMeetCall meetCall = (TLRPCCall.TL_UpdateMeetCall) args[0];
            if (meetCall != null && meetCall.id.equals(this.mChannel)) {
                this.mblnOtherIsPc = meetCall.isPc;
                return;
            }
            return;
        }
        if (id == NotificationCenter.reecivedAVideoDiscarded) {
            TLRPCCall.TL_UpdateMeetCallDiscarded discarded = (TLRPCCall.TL_UpdateMeetCallDiscarded) args[0];
            if (discarded != null && discarded.id.equals(this.mChannel)) {
                this.imgVisualcall.setEnabled(false);
                stopRtcAndService();
                int i = this.spConnectingId;
                if (i != 0) {
                    this.soundPool.stop(i);
                    this.spConnectingId = 0;
                }
                if (this.VisualCallType == 3) {
                    this.txtTip.setText(LocaleController.getString("visual_call_other_side_discard", R.string.visual_call_other_side_discard));
                    this.txtTip.setVisibility(0);
                    this.chrVisualcallTime.stop();
                    this.txtTip.postDelayed(new $$Lambda$tblfo3UtLqYImRKxPPOpLNJO68Q(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                    return;
                }
                if (this.mBlnReceiveFeedBack) {
                    this.txtTip.setText(LocaleController.getString("visual_call_other_side_discard", R.string.visual_call_other_side_discard));
                } else {
                    this.txtTip.setText(LocaleController.getString("visual_call_other_side_refuse", R.string.visual_call_other_side_refuse));
                }
                this.txtTip.setVisibility(0);
                setTipPos();
                this.mBlnReceiveFeedBack = true;
                this.txtTip.postDelayed(new $$Lambda$tblfo3UtLqYImRKxPPOpLNJO68Q(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                return;
            }
            return;
        }
        if (id == NotificationCenter.receivedAVideoCallAccept) {
            TLRPCCall.TL_UpdateMeetCallAccepted callAccepted = (TLRPCCall.TL_UpdateMeetCallAccepted) args[0];
            if (callAccepted != null && callAccepted.id.equals(this.mChannel)) {
                this.txtTip.setVisibility(8);
                this.mBlnReceiveFeedBack = true;
                if (this.callStyle == 2) {
                    this.dynamicPoint.animForWaitting(LocaleController.getString("visual_call_calling", R.string.visual_call_calling), this.txtVideoStatus);
                } else {
                    this.dynamicPoint.animForWaitting(LocaleController.getString("visual_call_calling", R.string.visual_call_calling), this.txtCallStatus);
                }
                int i2 = this.spConnectingId;
                if (i2 != 0) {
                    this.soundPool.stop(i2);
                    this.spConnectingId = 0;
                }
                openJoinChannelBeforeNeedParams();
                if (this.mGrantPermission) {
                    joinChannel();
                } else {
                    setUpSplash();
                }
                TLRPCCall.TL_UpdateMeetCallAccepted uca = (TLRPCCall.TL_UpdateMeetCallAccepted) args[0];
                AVideoCallInterface.ConfirmCall(uca.id, 0L, new AnonymousClass10());
                this.rel_video_user.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$hBaC_7iIy2Z1qAn16Cn0LIcRaAA
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$didReceivedNotification$10$VisualCallActivity();
                    }
                }, DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS);
                return;
            }
            return;
        }
        if (id == NotificationCenter.receivedAVideoCallBusy) {
            TLRPCCall.TL_UpdateMeetCallWaiting callWaiting = (TLRPCCall.TL_UpdateMeetCallWaiting) args[0];
            if (callWaiting != null && callWaiting.id.equals(this.mChannel)) {
                AVideoCallInterface.DiscardAVideoCall(this.mChannel, this.VISUAL_CALL_BUSY, this.callStyle == 2);
                stopRtcAndService();
                int i3 = this.spConnectingId;
                if (i3 != 0) {
                    this.soundPool.stop(i3);
                    this.spConnectingId = 0;
                }
                this.mBlnReceiveFeedBack = true;
                this.txtTip.setText(LocaleController.getString("visual_call_other_busing", R.string.visual_call_other_busing));
                this.txtTip.setVisibility(0);
                setTipPos();
                this.txtTip.postDelayed(new $$Lambda$tblfo3UtLqYImRKxPPOpLNJO68Q(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                return;
            }
            return;
        }
        if (id == NotificationCenter.receivedAVideoCallChangeVoice && (changeCall = (TLRPCCall.TL_UpdateMeetChangeCall) args[0]) != null && changeCall.id.equals(this.mChannel)) {
            this.callStyle = 1;
            changeToVoice(false);
            if (!this.mBlnReceiveFeedBack) {
                reInstallTimer();
            }
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity$10, reason: invalid class name */
    class AnonymousClass10 implements AVideoCallInterface.AVideoRequestCallBack {
        AnonymousClass10() {
        }

        @Override // im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface.AVideoRequestCallBack
        public void onError(TLRPC.TL_error error) {
        }

        @Override // im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface.AVideoRequestCallBack
        public void onSuccess(final TLObject object) {
            if (object instanceof TLRPCCall.TL_UpdateMeetCall) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$10$P1A-n2qMJOlSSjUwGqJgyfMUDRc
                    @Override // java.lang.Runnable
                    public final void run() {
                        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.receivedAVideoCallReady, object);
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$10$VisualCallActivity() {
        if (this.VisualCallType != 3) {
            this.txtTip.setVisibility(0);
            this.txtTip.setText(LocaleController.getString("visual_call_retry", R.string.visual_call_retry));
            setTipPos();
            stopRtcAndService();
            this.txtTip.postDelayed(new $$Lambda$tblfo3UtLqYImRKxPPOpLNJO68Q(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }
    }

    private void regNotification() {
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.receivedAVideoCallReady);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.reecivedAVideoDiscarded);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.receivedAVideoCallAccept);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.receivedAVideoCallBusy);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.receivedAVideoCallChangeVoice);
    }

    private void setFullScreen() {
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

    /* JADX INFO: Access modifiers changed from: private */
    public void stopRtcAndService() {
        if (ApplicationLoader.mbytAVideoCallBusy != 0) {
            ApplicationLoader.mbytAVideoCallBusy = (byte) 0;
            if (this.mForeServiceIntent != null && AppUtils.isServiceRunning(getApplicationContext(), ForegroundService.class.getName())) {
                stopService(this.mForeServiceIntent);
            }
            if (this.mAliRtcEngine != null) {
                new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$m5JpN837tAtEaRCEbGwR_puriLc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$stopRtcAndService$11$VisualCallActivity();
                    }
                }).start();
            }
            ConnectionsManager.getInstance(UserConfig.selectedAccount).setAppPaused(true, false);
        }
    }

    public /* synthetic */ void lambda$stopRtcAndService$11$VisualCallActivity() {
        this.mAliRtcEngine.setRtcEngineEventListener(null);
        if (this.callStyle == 2) {
            this.mAliRtcEngine.stopPreview();
        }
        this.mAliRtcEngine.leaveChannel();
        this.mAliRtcEngine.destroy();
        this.mAliRtcEngine = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setTipPos() {
        RelativeLayout.LayoutParams layoutParams = (RelativeLayout.LayoutParams) this.txtTip.getLayoutParams();
        if (this.rel_voice_user.getVisibility() == 8) {
            this.txtTip.setGravity(17);
        } else {
            layoutParams.addRule(3, R.attr.rel_voice_user);
            layoutParams.topMargin = AndroidUtilities.dp(25.0f);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void changeToVoice(boolean blnCaller) {
        DingRtcEngine dingRtcEngine = this.mAliRtcEngine;
        if (dingRtcEngine != null) {
            if (dingRtcEngine.isSpeakerphoneEnabled()) {
                this.mAliRtcEngine.enableSpeakerphone(false);
            }
            this.mAliRtcEngine.stopPreview();
        }
        changeStatusView();
        if (this.mbytIsForeground == 0) {
            this.mblnUnProcessChooseVoiceTip = true;
        } else {
            if (blnCaller) {
                this.txtTip.setText(LocaleController.getString(R.string.visual_call_caller_to_voice));
            } else {
                this.txtTip.setText(LocaleController.getString(R.string.visual_call_receive_to_voice));
            }
            setTipPos();
            this.txtTip.setVisibility(0);
            this.txtTip.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$1rhXp-k9ZqpuMBo7PidMzSjnIsU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$changeToVoice$12$VisualCallActivity();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }
        setHeadImage();
        if (this.VisualCallType != 3) {
            if (!this.mBlnReceiveFeedBack) {
                this.dynamicPoint.animForWaitting(LocaleController.getString(R.string.visual_call_waiting), this.txtCallStatus);
                return;
            } else {
                this.dynamicPoint.animForWaitting(LocaleController.getString(R.string.visual_call_calling), this.txtCallStatus);
                return;
            }
        }
        this.llBigWindow.setVisibility(8);
        this.chart_video_container.setVisibility(8);
    }

    public /* synthetic */ void lambda$changeToVoice$12$VisualCallActivity() {
        this.txtTip.setVisibility(8);
    }

    private void reInstallTimer() {
        this.mblnResetNoAnswer = true;
        this.chart_video_container.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$bV-Jq6BsilyVnrZJbjOW9jXKt28
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$reInstallTimer$13$VisualCallActivity();
            }
        }, 35000L);
        this.img_operate_a.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$Do3VYAfVw4cGSIoIzbPTR5aBQ-8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$reInstallTimer$14$VisualCallActivity();
            }
        }, 15000L);
    }

    public /* synthetic */ void lambda$reInstallTimer$13$VisualCallActivity() {
        if (!this.mBlnReceiveFeedBack) {
            processNoAnswer();
        }
    }

    public /* synthetic */ void lambda$reInstallTimer$14$VisualCallActivity() {
        if (!this.mBlnReceiveFeedBack) {
            processNoAnswerTip();
        }
    }
}
